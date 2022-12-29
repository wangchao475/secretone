package sessions

import (
	"bytes"
	"github.com/wangchao475/secretone/internals/api"
	shaws "github.com/wangchao475/secretone/internals/aws"
	"github.com/wangchao475/secretone/pkg/secretone/internals/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	// Currently always use the eu-west-1 region.
	defaultAWSRegionForSTS = endpoints.ApEast1RegionID
)

type awsSessionCreator struct {
	awsConfig []*aws.Config
}

// NewAWSSessionCreator returns a SessionCreator that uses AWS STS authentication to request sessions.
func NewAWSSessionCreator(awsCfg ...*aws.Config) SessionCreator {
	return &awsSessionCreator{
		awsConfig: awsCfg,
	}
}

// Create a new Session using AWS STS for authentication.
func (s *awsSessionCreator) Create(httpClient *http.Client) (Session, error) {
	region := defaultAWSRegionForSTS
	getCallerIdentityReq, out, err := getCallerIdentityRequest(region, s.awsConfig...)
	if err != nil {
		return nil, err
	}
	req := api.NewAuthRequestAWSSTS(api.SessionTypeHMAC, region, getCallerIdentityReq)
	resp, err := httpClient.CreateSession(out.Account, req)
	if err != nil {
		return nil, err
	}
	if resp.Type != api.SessionTypeHMAC {
		return nil, api.ErrInvalidSessionType
	}
	sess := resp.HMAC()

	return &hmacSession{
		sessionID:  sess.SessionID,
		sessionKey: sess.Payload.SessionKey,
		expireTime: expireTime(sess.Expires),
	}, nil
}

// getCallerIdentityRequest returns the raw bytes of a signed GetCallerIdentity request.
func getCallerIdentityRequest(region string, awsCfg ...*aws.Config) ([]byte, *sts.GetCallerIdentityOutput, error) {
	// Explicitly set the endpoint because the aws sdk by default uses the global endpoint.
	cfg := aws.NewConfig().WithRegion(region).WithEndpoint("sts." + region + ".amazonaws.com")
	awsSession, err := session.NewSession(append(awsCfg, cfg)...)
	if err != nil {
		return nil, nil, shaws.HandleError(err)
	}

	svc := sts.New(awsSession, cfg)
	identityRequest, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	identity, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, shaws.HandleError(err)
	}
	out := &sts.GetCallerIdentityOutput{
		UserId:  identity.UserId,
		Account: identity.Account,
		Arn:     identity.Arn,
	}
	// Sign the CallerIdentityRequest with the AWS access key
	err = identityRequest.Sign()
	if err != nil {
		return nil, nil, shaws.HandleError(err)
	}

	var buf bytes.Buffer
	err = identityRequest.HTTPRequest.Write(&buf)
	if err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), out, nil
}
