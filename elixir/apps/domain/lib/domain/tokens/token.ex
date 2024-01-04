# TODO: service accounts auth as clients and as API clients?
defmodule Domain.Tokens.Token do
  use Domain, :schema

  schema "tokens" do
    field :type, Ecto.Enum, values: [:browser, :client, :relay, :gateway, :email, :api_client]

    belongs_to :identity, Domain.Auth.Identity
    # belongs_to :relay_group, Domain.Relays.Group
    # belongs_to :gateway_group, Domain.Relays.Group

    # we store just hash(nonce+fragment+salt)
    field :secret_nonce, :string, virtual: true, redact: true
    field :secret_fragment, :string, virtual: true, redact: true
    field :secret_salt, :string, redact: true
    field :secret_hash, :string, redact: true

    belongs_to :account, Domain.Accounts.Account

    field :last_seen_user_agent, :string
    field :last_seen_remote_ip, Domain.Types.IP
    field :last_seen_remote_ip_location_region, :string
    field :last_seen_remote_ip_location_city, :string
    field :last_seen_remote_ip_location_lat, :float
    field :last_seen_remote_ip_location_lon, :float
    field :last_seen_at, :utc_datetime_usec

    # Maybe this is not needed and they should be in the join tables (eg. relay_group_tokens)
    field :created_by, Ecto.Enum, values: ~w[system identity]a
    belongs_to :created_by_identity, Domain.Auth.Identity
    field :created_by_user_agent, :string
    field :created_by_remote_ip, Domain.Types.IP

    field :expires_at, :utc_datetime_usec
    field :deleted_at, :utc_datetime_usec
    timestamps()
  end
end
