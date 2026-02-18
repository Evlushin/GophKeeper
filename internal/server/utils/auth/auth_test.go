package auth

import (
	"context"
	"github.com/Evlushin/GophKeeper/internal/server/models"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCtxUserID(t *testing.T) {
	type want struct {
		id  models.UserID
		err error
	}

	tests := []struct {
		name string
		ctx  context.Context
		want want
	}{
		{
			name: "success_user_in_context",
			ctx:  WithUser(t.Context(), models.UserID(42)),
			want: want{
				id:  models.UserID(42),
				err: nil,
			},
		},
		{
			name: "no_user_in_context",
			ctx:  t.Context(),
			want: want{
				id:  0,
				err: ErrUserNotFoundInContext,
			},
		},
		{
			name: "unexpected_type_in_context",
			ctx: func() context.Context {
				type wrongType struct{ v string }
				return context.WithValue(t.Context(), userCtxKey{}, wrongType{"not-a-userid"})
			}(),
			want: want{
				id:  0,
				err: ErrUnexpectedUserTypeInContext,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetCtxUserID(tt.ctx)
			if tt.want.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.want.err)
			}
			require.Equal(t, tt.want.id, got)
		})
	}
}

func TestWithUser_PutsCorrectType(t *testing.T) {
	const userID models.UserID = 7
	ctx := WithUser(t.Context(), userID)

	raw := ctx.Value(userCtxKey{})
	require.IsType(t, models.UserID(0), raw)
	rawUserID, ok := raw.(models.UserID)
	if !ok {
		t.Fatalf("failed to cast user")
	}
	require.Equal(t, models.UserID(7), rawUserID)
}
