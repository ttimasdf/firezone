defmodule Domain.Relays.Token.Changeset do
  use Domain, :changeset
  alias Domain.Auth
  alias Domain.Accounts
  alias Domain.Relays

  def create do
    %Relays.Token{}
    |> change()
    |> put_change(:value, Domain.Crypto.random_token(64))
    |> put_hash(:value, :argon2, to: :hash)
    |> assoc_constraint(:group)
    |> check_constraint(:hash, name: :hash_not_null, message: "can't be blank")
    |> put_change(:created_by, :system)
  end

  def create(%Accounts.Account{} = account, %Auth.Subject{} = subject) do
    create()
    |> put_change(:account_id, account.id)
    |> put_change(:created_by, :identity)
    |> put_change(:created_by_identity_id, subject.identity.id)
  end

  def use(%Relays.Token{} = token) do
    # TODO: While we don't have token rotation implemented, the tokens are all multi-use
    # delete(token)

    token
    |> change()
  end

  def delete(%Relays.Token{} = token) do
    token
    |> change()
    |> put_default_value(:deleted_at, DateTime.utc_now())
    |> put_change(:hash, nil)
    |> check_constraint(:hash, name: :hash_not_null, message: "must be blank")
  end
end
