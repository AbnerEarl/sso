// Code generated by ent, DO NOT EDIT.

package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/AbnerEarl/sso/provider/storage/ent/db/authcode"
)

// AuthCode is the model entity for the AuthCode schema.
type AuthCode struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id,omitempty"`
	// ClientID holds the value of the "client_id" field.
	ClientID string `json:"client_id,omitempty"`
	// Scopes holds the value of the "scopes" field.
	Scopes []string `json:"scopes,omitempty"`
	// Nonce holds the value of the "nonce" field.
	Nonce string `json:"nonce,omitempty"`
	// RedirectURI holds the value of the "redirect_uri" field.
	RedirectURI string `json:"redirect_uri,omitempty"`
	// ClaimsUserID holds the value of the "claims_user_id" field.
	ClaimsUserID string `json:"claims_user_id,omitempty"`
	// ClaimsUsername holds the value of the "claims_username" field.
	ClaimsUsername string `json:"claims_username,omitempty"`
	// ClaimsEmail holds the value of the "claims_email" field.
	ClaimsEmail string `json:"claims_email,omitempty"`
	// ClaimsEmailVerified holds the value of the "claims_email_verified" field.
	ClaimsEmailVerified bool `json:"claims_email_verified,omitempty"`
	// ClaimsGroups holds the value of the "claims_groups" field.
	ClaimsGroups []string `json:"claims_groups,omitempty"`
	// ClaimsPreferredUsername holds the value of the "claims_preferred_username" field.
	ClaimsPreferredUsername string `json:"claims_preferred_username,omitempty"`
	// ConnectorID holds the value of the "connector_id" field.
	ConnectorID string `json:"connector_id,omitempty"`
	// ConnectorData holds the value of the "connector_data" field.
	ConnectorData *[]byte `json:"connector_data,omitempty"`
	// Expiry holds the value of the "expiry" field.
	Expiry time.Time `json:"expiry,omitempty"`
	// CodeChallenge holds the value of the "code_challenge" field.
	CodeChallenge string `json:"code_challenge,omitempty"`
	// CodeChallengeMethod holds the value of the "code_challenge_method" field.
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	selectValues        sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AuthCode) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case authcode.FieldScopes, authcode.FieldClaimsGroups, authcode.FieldConnectorData:
			values[i] = new([]byte)
		case authcode.FieldClaimsEmailVerified:
			values[i] = new(sql.NullBool)
		case authcode.FieldID, authcode.FieldClientID, authcode.FieldNonce, authcode.FieldRedirectURI, authcode.FieldClaimsUserID, authcode.FieldClaimsUsername, authcode.FieldClaimsEmail, authcode.FieldClaimsPreferredUsername, authcode.FieldConnectorID, authcode.FieldCodeChallenge, authcode.FieldCodeChallengeMethod:
			values[i] = new(sql.NullString)
		case authcode.FieldExpiry:
			values[i] = new(sql.NullTime)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AuthCode fields.
func (ac *AuthCode) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case authcode.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				ac.ID = value.String
			}
		case authcode.FieldClientID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field client_id", values[i])
			} else if value.Valid {
				ac.ClientID = value.String
			}
		case authcode.FieldScopes:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field scopes", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ac.Scopes); err != nil {
					return fmt.Errorf("unmarshal field scopes: %w", err)
				}
			}
		case authcode.FieldNonce:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field nonce", values[i])
			} else if value.Valid {
				ac.Nonce = value.String
			}
		case authcode.FieldRedirectURI:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field redirect_uri", values[i])
			} else if value.Valid {
				ac.RedirectURI = value.String
			}
		case authcode.FieldClaimsUserID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field claims_user_id", values[i])
			} else if value.Valid {
				ac.ClaimsUserID = value.String
			}
		case authcode.FieldClaimsUsername:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field claims_username", values[i])
			} else if value.Valid {
				ac.ClaimsUsername = value.String
			}
		case authcode.FieldClaimsEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field claims_email", values[i])
			} else if value.Valid {
				ac.ClaimsEmail = value.String
			}
		case authcode.FieldClaimsEmailVerified:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field claims_email_verified", values[i])
			} else if value.Valid {
				ac.ClaimsEmailVerified = value.Bool
			}
		case authcode.FieldClaimsGroups:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field claims_groups", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ac.ClaimsGroups); err != nil {
					return fmt.Errorf("unmarshal field claims_groups: %w", err)
				}
			}
		case authcode.FieldClaimsPreferredUsername:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field claims_preferred_username", values[i])
			} else if value.Valid {
				ac.ClaimsPreferredUsername = value.String
			}
		case authcode.FieldConnectorID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field connector_id", values[i])
			} else if value.Valid {
				ac.ConnectorID = value.String
			}
		case authcode.FieldConnectorData:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field connector_data", values[i])
			} else if value != nil {
				ac.ConnectorData = value
			}
		case authcode.FieldExpiry:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field expiry", values[i])
			} else if value.Valid {
				ac.Expiry = value.Time
			}
		case authcode.FieldCodeChallenge:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field code_challenge", values[i])
			} else if value.Valid {
				ac.CodeChallenge = value.String
			}
		case authcode.FieldCodeChallengeMethod:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field code_challenge_method", values[i])
			} else if value.Valid {
				ac.CodeChallengeMethod = value.String
			}
		default:
			ac.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the AuthCode.
// This includes values selected through modifiers, order, etc.
func (ac *AuthCode) Value(name string) (ent.Value, error) {
	return ac.selectValues.Get(name)
}

// Update returns a builder for updating this AuthCode.
// Note that you need to call AuthCode.Unwrap() before calling this method if this AuthCode
// was returned from a transaction, and the transaction was committed or rolled back.
func (ac *AuthCode) Update() *AuthCodeUpdateOne {
	return NewAuthCodeClient(ac.config).UpdateOne(ac)
}

// Unwrap unwraps the AuthCode entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ac *AuthCode) Unwrap() *AuthCode {
	_tx, ok := ac.config.driver.(*txDriver)
	if !ok {
		panic("db: AuthCode is not a transactional entity")
	}
	ac.config.driver = _tx.drv
	return ac
}

// String implements the fmt.Stringer.
func (ac *AuthCode) String() string {
	var builder strings.Builder
	builder.WriteString("AuthCode(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ac.ID))
	builder.WriteString("client_id=")
	builder.WriteString(ac.ClientID)
	builder.WriteString(", ")
	builder.WriteString("scopes=")
	builder.WriteString(fmt.Sprintf("%v", ac.Scopes))
	builder.WriteString(", ")
	builder.WriteString("nonce=")
	builder.WriteString(ac.Nonce)
	builder.WriteString(", ")
	builder.WriteString("redirect_uri=")
	builder.WriteString(ac.RedirectURI)
	builder.WriteString(", ")
	builder.WriteString("claims_user_id=")
	builder.WriteString(ac.ClaimsUserID)
	builder.WriteString(", ")
	builder.WriteString("claims_username=")
	builder.WriteString(ac.ClaimsUsername)
	builder.WriteString(", ")
	builder.WriteString("claims_email=")
	builder.WriteString(ac.ClaimsEmail)
	builder.WriteString(", ")
	builder.WriteString("claims_email_verified=")
	builder.WriteString(fmt.Sprintf("%v", ac.ClaimsEmailVerified))
	builder.WriteString(", ")
	builder.WriteString("claims_groups=")
	builder.WriteString(fmt.Sprintf("%v", ac.ClaimsGroups))
	builder.WriteString(", ")
	builder.WriteString("claims_preferred_username=")
	builder.WriteString(ac.ClaimsPreferredUsername)
	builder.WriteString(", ")
	builder.WriteString("connector_id=")
	builder.WriteString(ac.ConnectorID)
	builder.WriteString(", ")
	if v := ac.ConnectorData; v != nil {
		builder.WriteString("connector_data=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	builder.WriteString("expiry=")
	builder.WriteString(ac.Expiry.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("code_challenge=")
	builder.WriteString(ac.CodeChallenge)
	builder.WriteString(", ")
	builder.WriteString("code_challenge_method=")
	builder.WriteString(ac.CodeChallengeMethod)
	builder.WriteByte(')')
	return builder.String()
}

// AuthCodes is a parsable slice of AuthCode.
type AuthCodes []*AuthCode
