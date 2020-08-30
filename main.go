package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/oladelmar/go-auth-api/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// TokenPair ...
type TokenPair struct {
	ID           primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID       string             `json:"user_id,omitempty" bson:"user_id,omitempty"`
	AccessToken  string             `json:"access_token,omitempty" bson:"access_token,omitempty"`
	RefreshToken string             `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
}

var client *mongo.Client
var db *mongo.Database
var tokensCollection *mongo.Collection

var accessTokenKey []byte
var refreshTokenKey []byte

func generateAccessToken(userID string, secret []byte) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)

	claims["user"] = userID
	claims["expires_at"] = time.Now().Add(time.Minute * 60).Unix()

	accessToken, err := token.SignedString(secret)

	if err != nil {
		log.Fatal(err)
		return "", err
	}
	return accessToken, nil
}

func generateRefreshToken(id string, secret []byte) (string, error) {
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)

	claims["id"] = id
	claims["expires_at"] = time.Now().Add(time.Hour * 24 * 90).Unix()

	refreshToken, err := token.SignedString(secret)

	if err != nil {
		log.Fatal(err)
		return "", err
	}
	return refreshToken, nil
}

func hashString(s string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(s), 10)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func compareTokens(hashedToken string, token string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token))
}

func respond(w http.ResponseWriter, r *http.Request, statusCode int, data interface{}) {
	w.WriteHeader(statusCode)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func handleError(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
	respond(w, r, statusCode, map[string]string{"error": err.Error()})
}

func handleCreateTokenPair() http.HandlerFunc {
	type request struct {
		UserID string `json:"user_id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var tokenPair TokenPair

		w.Header().Add("content-type", "application/json")
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			handleError(w, r, http.StatusBadRequest, err)
			return
		}

		accessToken, err := generateAccessToken(req.UserID, accessTokenKey)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		tokensCollection := db.Collection("tokens")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		tokenPair.UserID = req.UserID
		tokenPair.AccessToken = accessToken

		insertNewTokenPair := func(sessCtx mongo.SessionContext) (interface{}, error) {

			result, err := tokensCollection.InsertOne(ctx, tokenPair)
			if err != nil {
				return nil, err
			}

			insertID, ok := result.InsertedID.(primitive.ObjectID)
			if !ok {
				return nil, err
			}
			tokenPair.ID = insertID

			refreshToken, err := generateRefreshToken(insertID.Hex(), refreshTokenKey)
			if err != nil {
				return nil, err
			}

			refreshTokenHashed, err := hashString(refreshToken)
			if err != nil {
				return nil, err
			}
			tokenPair.RefreshToken = refreshTokenHashed

			_, err = tokensCollection.UpdateOne(
				ctx,
				bson.M{"_id": tokenPair.ID},
				bson.D{
					{"$set", bson.D{{"refresh_token", refreshTokenHashed}}},
				},
			)
			if err != nil {
				return nil, err
			}

			refreshTokenEncoded := base64.URLEncoding.EncodeToString([]byte(refreshToken))
			tokenPair.RefreshToken = refreshTokenEncoded
			return nil, nil
		}

		session, err := client.StartSession()
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		defer session.EndSession(ctx)

		_, err = session.WithTransaction(ctx, insertNewTokenPair)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		respond(w, r, http.StatusOK, tokenPair)
	}
}

func handleRefreshToken() http.HandlerFunc {
	type request struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	type refreshTokenClaims struct {
		ID        string `json:"id"`
		ExpiresAt int64  `json:"expires_at"`
		jwt.StandardClaims
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var tokenPair TokenPair
		var primitiveID primitive.ObjectID
		var stringID string
		var refreshTokenExpiresAt int64

		w.Header().Add("content-type", "application/json")
		req := &request{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			handleError(w, r, http.StatusBadRequest, err)
			return
		}

		accessToken := req.AccessToken
		refreshTokenEncoded := req.RefreshToken
		refreshTokenBytes, err := base64.URLEncoding.DecodeString(refreshTokenEncoded) // refresh in []byte format
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		refreshToken := string(refreshTokenBytes)

		refreshTokenParsed, err := jwt.ParseWithClaims(refreshToken, &refreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("Not authorized")
			}
			return refreshTokenKey, nil
		})
		if err != nil {
			handleError(w, r, http.StatusUnauthorized, err)
			return
		}

		if claims, ok := refreshTokenParsed.Claims.(*refreshTokenClaims); ok && refreshTokenParsed.Valid {
			stringID = claims.ID
			primitiveID, _ = primitive.ObjectIDFromHex(claims.ID)
			refreshTokenExpiresAt = claims.ExpiresAt
		} else {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		timeNow := time.Now().Unix()
		if refreshTokenExpiresAt < timeNow {
			respond(w, r, http.StatusUnauthorized, nil)
			return
		}

		tokensCollection := db.Collection("tokens")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		if err = tokensCollection.FindOne(ctx, TokenPair{ID: primitiveID, AccessToken: accessToken}).Decode(&tokenPair); err != nil {
			respond(w, r, http.StatusNotFound, err)
			return
		}

		err = compareTokens(tokenPair.RefreshToken, refreshToken)
		if err != nil {
			handleError(w, r, http.StatusUnauthorized, errors.New("Invalid token"))
			return
		}

		newAccessToken, err := generateAccessToken(tokenPair.UserID, accessTokenKey)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		tokenPair.AccessToken = newAccessToken

		newRefreshToken, err := generateRefreshToken(stringID, refreshTokenKey)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		newRefreshTokenHashed, err := hashString(newRefreshToken)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		_, err = tokensCollection.UpdateOne(
			ctx,
			bson.M{"_id": tokenPair.ID},
			bson.D{
				{"$set", bson.D{{"refresh_token", newRefreshTokenHashed}, {"access_token", newAccessToken}}},
			},
		)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		newRefreshTokenEncoded := base64.URLEncoding.EncodeToString([]byte(newRefreshToken))
		tokenPair.RefreshToken = newRefreshTokenEncoded

		respond(w, r, http.StatusOK, tokenPair)
	}
}

func handleDeleteOneToken() http.HandlerFunc {
	type refreshTokenClaims struct {
		ID        string `json:"id"`
		ExpiresAt int64  `json:"expires_at"`
		jwt.StandardClaims
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var id primitive.ObjectID

		w.Header().Add("content-type", "application/json")

		params := mux.Vars(r)
		refreshTokenEncoded := params["refresh_token"]
		refreshTokenBytes, err := base64.URLEncoding.DecodeString(refreshTokenEncoded) // refresh token in []byte format
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		refreshToken := string(refreshTokenBytes)

		refreshTokenParsed, err := jwt.ParseWithClaims(refreshToken, &refreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("Not authorized")
			}
			return refreshTokenKey, nil
		})
		if err != nil {
			handleError(w, r, http.StatusUnauthorized, err)
			return
		}

		if claims, ok := refreshTokenParsed.Claims.(*refreshTokenClaims); ok && refreshTokenParsed.Valid {
			id, _ = primitive.ObjectIDFromHex(claims.ID)
		} else {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		tokensCollection := db.Collection("tokens")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		var tokenPair TokenPair
		if err = tokensCollection.FindOne(ctx, TokenPair{ID: id}).Decode(&tokenPair); err != nil {
			respond(w, r, http.StatusNotFound, err)
			return
		}

		err = compareTokens(tokenPair.RefreshToken, refreshToken)
		if err != nil {
			handleError(w, r, http.StatusUnauthorized, errors.New("Invalid token"))
			return
		}

		var deletedDocument bson.M
		err = tokensCollection.FindOneAndDelete(ctx, TokenPair{ID: id}).Decode(&deletedDocument)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				handleError(w, r, http.StatusNotFound, err)
				return
			}
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		respond(w, r, http.StatusNoContent, nil)
	}
}

func handleDeleteAllTokensForUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "application/json")

		params := mux.Vars(r)
		userID := params["user_id"]

		tokensCollection := db.Collection("tokens")
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		deleteMany := func(sessCtx mongo.SessionContext) (interface{}, error) {
			if _, err := tokensCollection.DeleteMany(ctx, TokenPair{UserID: userID}); err != nil {
				return nil, err
			}
			return nil, nil
		}

		session, err := client.StartSession()
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}
		defer session.EndSession(ctx)

		_, err = session.WithTransaction(ctx, deleteMany)
		if err != nil {
			handleError(w, r, http.StatusInternalServerError, err)
			return
		}

		// ===================== WITHOUT TRANSACTIONS =============================
		// _, err := tokensCollection.DeleteMany(ctx, TokenPair{UserID: userID})
		// if err != nil {
		// 	if err == mongo.ErrNoDocuments {
		// 		handleError(w, r, http.StatusNotFound, err)
		// 		return
		// 	}
		// 	handleError(w, r, http.StatusInternalServerError, err)
		// 	return
		// }
		respond(w, r, http.StatusNoContent, nil)
	}
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	env := config.New()
	port := os.Getenv("PORT")
	accessTokenKey = []byte(env.AccessTokenKey)
	refreshTokenKey = []byte(env.RefreshTokenKey)

	log.Println("App running on port " + env.Port + " ...")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://"+env.DBUser+":"+env.DBPassword+"@cluster0.s9vst.mongodb.net/"+env.DBName))

	if err != nil {
		log.Fatal(err)
	}

	defer client.Disconnect(ctx)
	db = client.Database(env.DBName)

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/auth/tokens", handleCreateTokenPair()).Methods("POST")
	router.HandleFunc("/api/v1/auth/tokens", handleRefreshToken()).Methods("PUT") // pass access token and refresh token in the body
	router.HandleFunc("/api/v1/auth/tokens/{refresh_token}", handleDeleteOneToken()).Methods("DELETE")
	router.HandleFunc("/api/v1/auth/tokens/users/{user_id}", handleDeleteAllTokensForUser()).Methods("DELETE")

	http.ListenAndServe(":"+port, router)

}
