package music

import (
	"context"
	"database/sql"
	"fmt"
	"music-auth/internal/middleware"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type MusicService struct {
	db         *sql.DB
	S3Uploader *manager.Uploader
	S3Client   *s3.Client
	S3Bucket   string
	Presigner  *s3.PresignClient
	CDN        string
}

func New(db *sql.DB, uploader *manager.Uploader, client *s3.Client, cdn, bucket string) *MusicService {
	return &MusicService{
		db:         db,
		S3Uploader: uploader,
		S3Client:   client,
		S3Bucket:   bucket,
		Presigner:  s3.NewPresignClient(client),
		CDN:        cdn,
	}
}

func (m *MusicService) CreatePresignedForPUTRequest(fileName, contentType, key string) (string, error) {
	req, err := m.Presigner.PresignPutObject(
		context.TODO(),
		&s3.PutObjectInput{
			Bucket:      aws.String(m.S3Bucket),
			Key:         aws.String(key),
			ContentType: aws.String(contentType),
		},
		func(opts *s3.PresignOptions) {
			opts.Expires = 15 * time.Minute
		},
	)
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (m *MusicService) GetPresignedURLForTrackUploading(ctx context.Context, filename, contentType string) (string, string, error) {

	_, ok := middleware.GetUserFromContext(ctx)

	if !ok {
		return "", "", fmt.Errorf("unauthorized")
	}

	if filename == "" {
		return "", "", fmt.Errorf("filename is required")
	}
	if contentType == "" {
		return "", "", fmt.Errorf("content-type is required")
	}

	key := fmt.Sprintf("tracks/%d-%s", time.Now().UnixMilli(), filename)

	url, err := m.CreatePresignedForPUTRequest(filename, contentType, key)

	if err != nil {
		return "", "", fmt.Errorf("%s", err.Error())
	}

	return url, key, nil

}

func (m *MusicService) SaveTrackInDB(ctx context.Context, albumID *uuid.UUID, title, artist, genre, format, key string, duration, fileSize int32) (error) {
	claims, ok := middleware.GetUserFromContext(ctx)

	if !ok {
		return fmt.Errorf("unauthorized")
	}

	userID := claims.UserID

	query := `
        INSERT INTO tracks (user_id, album_id, title, artist, genre, duration, file_size, format, key, cdn_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `

	_, err := m.db.Exec(query,
		userID,
		albumID,
		title,
		artist,
		genre,
		duration,
		fileSize,
		format,
		key,
		m.CDN+"/"+key,
	)
	if err != nil {
		return fmt.Errorf("failed to save track: %w", err)
	}

	return nil
}
