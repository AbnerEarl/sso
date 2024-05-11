// Code generated by ent, DO NOT EDIT.

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	jose "github.com/AbnerEarl/sso/jose"
	"github.com/AbnerEarl/sso/provider/storage"
	"github.com/AbnerEarl/sso/provider/storage/ent/db/keys"
)

// KeysCreate is the builder for creating a Keys entity.
type KeysCreate struct {
	config
	mutation *KeysMutation
	hooks    []Hook
}

// SetVerificationKeys sets the "verification_keys" field.
func (kc *KeysCreate) SetVerificationKeys(sk []storage.VerificationKey) *KeysCreate {
	kc.mutation.SetVerificationKeys(sk)
	return kc
}

// SetSigningKey sets the "signing_key" field.
func (kc *KeysCreate) SetSigningKey(jwk jose.JSONWebKey) *KeysCreate {
	kc.mutation.SetSigningKey(jwk)
	return kc
}

// SetSigningKeyPub sets the "signing_key_pub" field.
func (kc *KeysCreate) SetSigningKeyPub(jwk jose.JSONWebKey) *KeysCreate {
	kc.mutation.SetSigningKeyPub(jwk)
	return kc
}

// SetNextRotation sets the "next_rotation" field.
func (kc *KeysCreate) SetNextRotation(t time.Time) *KeysCreate {
	kc.mutation.SetNextRotation(t)
	return kc
}

// SetID sets the "id" field.
func (kc *KeysCreate) SetID(s string) *KeysCreate {
	kc.mutation.SetID(s)
	return kc
}

// Mutation returns the KeysMutation object of the builder.
func (kc *KeysCreate) Mutation() *KeysMutation {
	return kc.mutation
}

// Save creates the Keys in the database.
func (kc *KeysCreate) Save(ctx context.Context) (*Keys, error) {
	return withHooks(ctx, kc.sqlSave, kc.mutation, kc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (kc *KeysCreate) SaveX(ctx context.Context) *Keys {
	v, err := kc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (kc *KeysCreate) Exec(ctx context.Context) error {
	_, err := kc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (kc *KeysCreate) ExecX(ctx context.Context) {
	if err := kc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (kc *KeysCreate) check() error {
	if _, ok := kc.mutation.VerificationKeys(); !ok {
		return &ValidationError{Name: "verification_keys", err: errors.New(`db: missing required field "Keys.verification_keys"`)}
	}
	if _, ok := kc.mutation.SigningKey(); !ok {
		return &ValidationError{Name: "signing_key", err: errors.New(`db: missing required field "Keys.signing_key"`)}
	}
	if _, ok := kc.mutation.SigningKeyPub(); !ok {
		return &ValidationError{Name: "signing_key_pub", err: errors.New(`db: missing required field "Keys.signing_key_pub"`)}
	}
	if _, ok := kc.mutation.NextRotation(); !ok {
		return &ValidationError{Name: "next_rotation", err: errors.New(`db: missing required field "Keys.next_rotation"`)}
	}
	if v, ok := kc.mutation.ID(); ok {
		if err := keys.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`db: validator failed for field "Keys.id": %w`, err)}
		}
	}
	return nil
}

func (kc *KeysCreate) sqlSave(ctx context.Context) (*Keys, error) {
	if err := kc.check(); err != nil {
		return nil, err
	}
	_node, _spec := kc.createSpec()
	if err := sqlgraph.CreateNode(ctx, kc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected Keys.ID type: %T", _spec.ID.Value)
		}
	}
	kc.mutation.id = &_node.ID
	kc.mutation.done = true
	return _node, nil
}

func (kc *KeysCreate) createSpec() (*Keys, *sqlgraph.CreateSpec) {
	var (
		_node = &Keys{config: kc.config}
		_spec = sqlgraph.NewCreateSpec(keys.Table, sqlgraph.NewFieldSpec(keys.FieldID, field.TypeString))
	)
	if id, ok := kc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := kc.mutation.VerificationKeys(); ok {
		_spec.SetField(keys.FieldVerificationKeys, field.TypeJSON, value)
		_node.VerificationKeys = value
	}
	if value, ok := kc.mutation.SigningKey(); ok {
		_spec.SetField(keys.FieldSigningKey, field.TypeJSON, value)
		_node.SigningKey = value
	}
	if value, ok := kc.mutation.SigningKeyPub(); ok {
		_spec.SetField(keys.FieldSigningKeyPub, field.TypeJSON, value)
		_node.SigningKeyPub = value
	}
	if value, ok := kc.mutation.NextRotation(); ok {
		_spec.SetField(keys.FieldNextRotation, field.TypeTime, value)
		_node.NextRotation = value
	}
	return _node, _spec
}

// KeysCreateBulk is the builder for creating many Keys entities in bulk.
type KeysCreateBulk struct {
	config
	err      error
	builders []*KeysCreate
}

// Save creates the Keys entities in the database.
func (kcb *KeysCreateBulk) Save(ctx context.Context) ([]*Keys, error) {
	if kcb.err != nil {
		return nil, kcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(kcb.builders))
	nodes := make([]*Keys, len(kcb.builders))
	mutators := make([]Mutator, len(kcb.builders))
	for i := range kcb.builders {
		func(i int, root context.Context) {
			builder := kcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*KeysMutation)
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
					_, err = mutators[i+1].Mutate(root, kcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, kcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, kcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (kcb *KeysCreateBulk) SaveX(ctx context.Context) []*Keys {
	v, err := kcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (kcb *KeysCreateBulk) Exec(ctx context.Context) error {
	_, err := kcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (kcb *KeysCreateBulk) ExecX(ctx context.Context) {
	if err := kcb.Exec(ctx); err != nil {
		panic(err)
	}
}
