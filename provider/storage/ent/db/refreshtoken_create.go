// Code generated by ent, DO NOT EDIT.

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/AbnerEarl/sso/provider/storage/ent/db/refreshtoken"
)

// RefreshTokenCreate is the builder for creating a RefreshToken entity.
type RefreshTokenCreate struct {
	config
	mutation *RefreshTokenMutation
	hooks    []Hook
}

// SetClientID sets the "client_id" field.
func (rtc *RefreshTokenCreate) SetClientID(s string) *RefreshTokenCreate {
	rtc.mutation.SetClientID(s)
	return rtc
}

// SetScopes sets the "scopes" field.
func (rtc *RefreshTokenCreate) SetScopes(s []string) *RefreshTokenCreate {
	rtc.mutation.SetScopes(s)
	return rtc
}

// SetNonce sets the "nonce" field.
func (rtc *RefreshTokenCreate) SetNonce(s string) *RefreshTokenCreate {
	rtc.mutation.SetNonce(s)
	return rtc
}

// SetClaimsUserID sets the "claims_user_id" field.
func (rtc *RefreshTokenCreate) SetClaimsUserID(s string) *RefreshTokenCreate {
	rtc.mutation.SetClaimsUserID(s)
	return rtc
}

// SetClaimsUsername sets the "claims_username" field.
func (rtc *RefreshTokenCreate) SetClaimsUsername(s string) *RefreshTokenCreate {
	rtc.mutation.SetClaimsUsername(s)
	return rtc
}

// SetClaimsEmail sets the "claims_email" field.
func (rtc *RefreshTokenCreate) SetClaimsEmail(s string) *RefreshTokenCreate {
	rtc.mutation.SetClaimsEmail(s)
	return rtc
}

// SetClaimsEmailVerified sets the "claims_email_verified" field.
func (rtc *RefreshTokenCreate) SetClaimsEmailVerified(b bool) *RefreshTokenCreate {
	rtc.mutation.SetClaimsEmailVerified(b)
	return rtc
}

// SetClaimsGroups sets the "claims_groups" field.
func (rtc *RefreshTokenCreate) SetClaimsGroups(s []string) *RefreshTokenCreate {
	rtc.mutation.SetClaimsGroups(s)
	return rtc
}

// SetClaimsPreferredUsername sets the "claims_preferred_username" field.
func (rtc *RefreshTokenCreate) SetClaimsPreferredUsername(s string) *RefreshTokenCreate {
	rtc.mutation.SetClaimsPreferredUsername(s)
	return rtc
}

// SetNillableClaimsPreferredUsername sets the "claims_preferred_username" field if the given value is not nil.
func (rtc *RefreshTokenCreate) SetNillableClaimsPreferredUsername(s *string) *RefreshTokenCreate {
	if s != nil {
		rtc.SetClaimsPreferredUsername(*s)
	}
	return rtc
}

// SetConnectorID sets the "connector_id" field.
func (rtc *RefreshTokenCreate) SetConnectorID(s string) *RefreshTokenCreate {
	rtc.mutation.SetConnectorID(s)
	return rtc
}

// SetConnectorData sets the "connector_data" field.
func (rtc *RefreshTokenCreate) SetConnectorData(b []byte) *RefreshTokenCreate {
	rtc.mutation.SetConnectorData(b)
	return rtc
}

// SetToken sets the "token" field.
func (rtc *RefreshTokenCreate) SetToken(s string) *RefreshTokenCreate {
	rtc.mutation.SetToken(s)
	return rtc
}

// SetNillableToken sets the "token" field if the given value is not nil.
func (rtc *RefreshTokenCreate) SetNillableToken(s *string) *RefreshTokenCreate {
	if s != nil {
		rtc.SetToken(*s)
	}
	return rtc
}

// SetObsoleteToken sets the "obsolete_token" field.
func (rtc *RefreshTokenCreate) SetObsoleteToken(s string) *RefreshTokenCreate {
	rtc.mutation.SetObsoleteToken(s)
	return rtc
}

// SetNillableObsoleteToken sets the "obsolete_token" field if the given value is not nil.
func (rtc *RefreshTokenCreate) SetNillableObsoleteToken(s *string) *RefreshTokenCreate {
	if s != nil {
		rtc.SetObsoleteToken(*s)
	}
	return rtc
}

// SetCreatedAt sets the "created_at" field.
func (rtc *RefreshTokenCreate) SetCreatedAt(t time.Time) *RefreshTokenCreate {
	rtc.mutation.SetCreatedAt(t)
	return rtc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rtc *RefreshTokenCreate) SetNillableCreatedAt(t *time.Time) *RefreshTokenCreate {
	if t != nil {
		rtc.SetCreatedAt(*t)
	}
	return rtc
}

// SetLastUsed sets the "last_used" field.
func (rtc *RefreshTokenCreate) SetLastUsed(t time.Time) *RefreshTokenCreate {
	rtc.mutation.SetLastUsed(t)
	return rtc
}

// SetNillableLastUsed sets the "last_used" field if the given value is not nil.
func (rtc *RefreshTokenCreate) SetNillableLastUsed(t *time.Time) *RefreshTokenCreate {
	if t != nil {
		rtc.SetLastUsed(*t)
	}
	return rtc
}

// SetID sets the "id" field.
func (rtc *RefreshTokenCreate) SetID(s string) *RefreshTokenCreate {
	rtc.mutation.SetID(s)
	return rtc
}

// Mutation returns the RefreshTokenMutation object of the builder.
func (rtc *RefreshTokenCreate) Mutation() *RefreshTokenMutation {
	return rtc.mutation
}

// Save creates the RefreshToken in the database.
func (rtc *RefreshTokenCreate) Save(ctx context.Context) (*RefreshToken, error) {
	rtc.defaults()
	return withHooks(ctx, rtc.sqlSave, rtc.mutation, rtc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (rtc *RefreshTokenCreate) SaveX(ctx context.Context) *RefreshToken {
	v, err := rtc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rtc *RefreshTokenCreate) Exec(ctx context.Context) error {
	_, err := rtc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rtc *RefreshTokenCreate) ExecX(ctx context.Context) {
	if err := rtc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rtc *RefreshTokenCreate) defaults() {
	if _, ok := rtc.mutation.ClaimsPreferredUsername(); !ok {
		v := refreshtoken.DefaultClaimsPreferredUsername
		rtc.mutation.SetClaimsPreferredUsername(v)
	}
	if _, ok := rtc.mutation.Token(); !ok {
		v := refreshtoken.DefaultToken
		rtc.mutation.SetToken(v)
	}
	if _, ok := rtc.mutation.ObsoleteToken(); !ok {
		v := refreshtoken.DefaultObsoleteToken
		rtc.mutation.SetObsoleteToken(v)
	}
	if _, ok := rtc.mutation.CreatedAt(); !ok {
		v := refreshtoken.DefaultCreatedAt()
		rtc.mutation.SetCreatedAt(v)
	}
	if _, ok := rtc.mutation.LastUsed(); !ok {
		v := refreshtoken.DefaultLastUsed()
		rtc.mutation.SetLastUsed(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rtc *RefreshTokenCreate) check() error {
	if _, ok := rtc.mutation.ClientID(); !ok {
		return &ValidationError{Name: "client_id", err: errors.New(`db: missing required field "RefreshToken.client_id"`)}
	}
	if v, ok := rtc.mutation.ClientID(); ok {
		if err := refreshtoken.ClientIDValidator(v); err != nil {
			return &ValidationError{Name: "client_id", err: fmt.Errorf(`db: validator failed for field "RefreshToken.client_id": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.Nonce(); !ok {
		return &ValidationError{Name: "nonce", err: errors.New(`db: missing required field "RefreshToken.nonce"`)}
	}
	if v, ok := rtc.mutation.Nonce(); ok {
		if err := refreshtoken.NonceValidator(v); err != nil {
			return &ValidationError{Name: "nonce", err: fmt.Errorf(`db: validator failed for field "RefreshToken.nonce": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.ClaimsUserID(); !ok {
		return &ValidationError{Name: "claims_user_id", err: errors.New(`db: missing required field "RefreshToken.claims_user_id"`)}
	}
	if v, ok := rtc.mutation.ClaimsUserID(); ok {
		if err := refreshtoken.ClaimsUserIDValidator(v); err != nil {
			return &ValidationError{Name: "claims_user_id", err: fmt.Errorf(`db: validator failed for field "RefreshToken.claims_user_id": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.ClaimsUsername(); !ok {
		return &ValidationError{Name: "claims_username", err: errors.New(`db: missing required field "RefreshToken.claims_username"`)}
	}
	if v, ok := rtc.mutation.ClaimsUsername(); ok {
		if err := refreshtoken.ClaimsUsernameValidator(v); err != nil {
			return &ValidationError{Name: "claims_username", err: fmt.Errorf(`db: validator failed for field "RefreshToken.claims_username": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.ClaimsEmail(); !ok {
		return &ValidationError{Name: "claims_email", err: errors.New(`db: missing required field "RefreshToken.claims_email"`)}
	}
	if v, ok := rtc.mutation.ClaimsEmail(); ok {
		if err := refreshtoken.ClaimsEmailValidator(v); err != nil {
			return &ValidationError{Name: "claims_email", err: fmt.Errorf(`db: validator failed for field "RefreshToken.claims_email": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.ClaimsEmailVerified(); !ok {
		return &ValidationError{Name: "claims_email_verified", err: errors.New(`db: missing required field "RefreshToken.claims_email_verified"`)}
	}
	if _, ok := rtc.mutation.ClaimsPreferredUsername(); !ok {
		return &ValidationError{Name: "claims_preferred_username", err: errors.New(`db: missing required field "RefreshToken.claims_preferred_username"`)}
	}
	if _, ok := rtc.mutation.ConnectorID(); !ok {
		return &ValidationError{Name: "connector_id", err: errors.New(`db: missing required field "RefreshToken.connector_id"`)}
	}
	if v, ok := rtc.mutation.ConnectorID(); ok {
		if err := refreshtoken.ConnectorIDValidator(v); err != nil {
			return &ValidationError{Name: "connector_id", err: fmt.Errorf(`db: validator failed for field "RefreshToken.connector_id": %w`, err)}
		}
	}
	if _, ok := rtc.mutation.Token(); !ok {
		return &ValidationError{Name: "token", err: errors.New(`db: missing required field "RefreshToken.token"`)}
	}
	if _, ok := rtc.mutation.ObsoleteToken(); !ok {
		return &ValidationError{Name: "obsolete_token", err: errors.New(`db: missing required field "RefreshToken.obsolete_token"`)}
	}
	if _, ok := rtc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`db: missing required field "RefreshToken.created_at"`)}
	}
	if _, ok := rtc.mutation.LastUsed(); !ok {
		return &ValidationError{Name: "last_used", err: errors.New(`db: missing required field "RefreshToken.last_used"`)}
	}
	if v, ok := rtc.mutation.ID(); ok {
		if err := refreshtoken.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`db: validator failed for field "RefreshToken.id": %w`, err)}
		}
	}
	return nil
}

func (rtc *RefreshTokenCreate) sqlSave(ctx context.Context) (*RefreshToken, error) {
	if err := rtc.check(); err != nil {
		return nil, err
	}
	_node, _spec := rtc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rtc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected RefreshToken.ID type: %T", _spec.ID.Value)
		}
	}
	rtc.mutation.id = &_node.ID
	rtc.mutation.done = true
	return _node, nil
}

func (rtc *RefreshTokenCreate) createSpec() (*RefreshToken, *sqlgraph.CreateSpec) {
	var (
		_node = &RefreshToken{config: rtc.config}
		_spec = sqlgraph.NewCreateSpec(refreshtoken.Table, sqlgraph.NewFieldSpec(refreshtoken.FieldID, field.TypeString))
	)
	if id, ok := rtc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := rtc.mutation.ClientID(); ok {
		_spec.SetField(refreshtoken.FieldClientID, field.TypeString, value)
		_node.ClientID = value
	}
	if value, ok := rtc.mutation.Scopes(); ok {
		_spec.SetField(refreshtoken.FieldScopes, field.TypeJSON, value)
		_node.Scopes = value
	}
	if value, ok := rtc.mutation.Nonce(); ok {
		_spec.SetField(refreshtoken.FieldNonce, field.TypeString, value)
		_node.Nonce = value
	}
	if value, ok := rtc.mutation.ClaimsUserID(); ok {
		_spec.SetField(refreshtoken.FieldClaimsUserID, field.TypeString, value)
		_node.ClaimsUserID = value
	}
	if value, ok := rtc.mutation.ClaimsUsername(); ok {
		_spec.SetField(refreshtoken.FieldClaimsUsername, field.TypeString, value)
		_node.ClaimsUsername = value
	}
	if value, ok := rtc.mutation.ClaimsEmail(); ok {
		_spec.SetField(refreshtoken.FieldClaimsEmail, field.TypeString, value)
		_node.ClaimsEmail = value
	}
	if value, ok := rtc.mutation.ClaimsEmailVerified(); ok {
		_spec.SetField(refreshtoken.FieldClaimsEmailVerified, field.TypeBool, value)
		_node.ClaimsEmailVerified = value
	}
	if value, ok := rtc.mutation.ClaimsGroups(); ok {
		_spec.SetField(refreshtoken.FieldClaimsGroups, field.TypeJSON, value)
		_node.ClaimsGroups = value
	}
	if value, ok := rtc.mutation.ClaimsPreferredUsername(); ok {
		_spec.SetField(refreshtoken.FieldClaimsPreferredUsername, field.TypeString, value)
		_node.ClaimsPreferredUsername = value
	}
	if value, ok := rtc.mutation.ConnectorID(); ok {
		_spec.SetField(refreshtoken.FieldConnectorID, field.TypeString, value)
		_node.ConnectorID = value
	}
	if value, ok := rtc.mutation.ConnectorData(); ok {
		_spec.SetField(refreshtoken.FieldConnectorData, field.TypeBytes, value)
		_node.ConnectorData = &value
	}
	if value, ok := rtc.mutation.Token(); ok {
		_spec.SetField(refreshtoken.FieldToken, field.TypeString, value)
		_node.Token = value
	}
	if value, ok := rtc.mutation.ObsoleteToken(); ok {
		_spec.SetField(refreshtoken.FieldObsoleteToken, field.TypeString, value)
		_node.ObsoleteToken = value
	}
	if value, ok := rtc.mutation.CreatedAt(); ok {
		_spec.SetField(refreshtoken.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := rtc.mutation.LastUsed(); ok {
		_spec.SetField(refreshtoken.FieldLastUsed, field.TypeTime, value)
		_node.LastUsed = value
	}
	return _node, _spec
}

// RefreshTokenCreateBulk is the builder for creating many RefreshToken entities in bulk.
type RefreshTokenCreateBulk struct {
	config
	err      error
	builders []*RefreshTokenCreate
}

// Save creates the RefreshToken entities in the database.
func (rtcb *RefreshTokenCreateBulk) Save(ctx context.Context) ([]*RefreshToken, error) {
	if rtcb.err != nil {
		return nil, rtcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(rtcb.builders))
	nodes := make([]*RefreshToken, len(rtcb.builders))
	mutators := make([]Mutator, len(rtcb.builders))
	for i := range rtcb.builders {
		func(i int, root context.Context) {
			builder := rtcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*RefreshTokenMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, rtcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rtcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, rtcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rtcb *RefreshTokenCreateBulk) SaveX(ctx context.Context) []*RefreshToken {
	v, err := rtcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rtcb *RefreshTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := rtcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rtcb *RefreshTokenCreateBulk) ExecX(ctx context.Context) {
	if err := rtcb.Exec(ctx); err != nil {
		panic(err)
	}
}
