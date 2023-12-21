defmodule Domain.Auth do
  @doc """
  This module is the core of our security, it is designed to have multiple layers of
  protection and provide guidance for the developers to avoid common security pitfalls.

  ## Authentication

  Authentication is split into two core components:

  1. *Sign In* - exchange of a secret (IdP ID token or username/password) for our internal token.

     This token is stored in the database (see `Domain.Tokens` module) and then encoded to be
     stored in browser session or on mobile clients. For more details see "Tokens" section below.

  2. Authentication - verification of the token and extraction of the subject from it.

  ## Authorization and Subject

  Authorization is a domain concern because it's tightly coupled with the business logic
  and allows better control over the access to the data. Plus makes it more secure iterating
  faster on the UI/UX without risking to compromise security.

  Every function directly or indirectly called by the end user MUST have a Subject
  as last or second to last argument, implementation of the functions MUST use
  it's own context `Authroizer` module (that implements behaviour `Domain.Auth.Authorizer`)
  to filter the data based on the account and permissions of the subject.

  As an extra measure, whenever a function performs an action on an object that is not
  further re-queried using the `for_subject/1` the implementation MUST check that the subject
  has access to given object. It can be done by one of `ensure_has_access_to?/2` functions
  added to domain contexts responsible for the given schema, eg. `Domain.Accounts.ensure_has_access_to/2`.

  Only exception is the authentication flow where user can not contain the subject yet,
  but such queries MUST be filtered by the `account_id` and use indexes to prevent
  simple DDoS attacks.

  ## Tokens

  The tokens are color coded using `type` field, which means that token issues for browser session
  can not be used for client calls and vice versa. Type of the token also limits permissions that will
  be later added to the subject.

  Token is additionally signed and encrypted using `Phoenix.Token` to prevent tampering with it
  and to prevent database lookups for invalid tokens. See `Domain.Tokens.encode_token!/1` for
  more details.

  Token expiration depends on context in which it can be used and is limited by
  `@max_session_duration_hours` to prevent extremely long-lived tokens for
  `clients` and `browsers`. Fore more details see `Domain.Tokens.token_expires_at/2`.
  """
  use Supervisor
  alias Domain.{Repo, Validator}
  alias Domain.{Accounts, Actors, Tokens}
  alias Domain.Auth.{Authorizer, Subject, Context, Permission, Roles, Role}
  alias Domain.Auth.{Adapters, Provider}
  alias Domain.Auth.Identity

  @default_session_duration_hours [
    browser: [
      account_admin_user: 10,
      account_user: 10
    ],
    client: [
      account_admin_user: 24 * 7,
      account_user: 24 * 7
    ]
  ]

  @max_session_duration_hours @default_session_duration_hours

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    children = [
      Adapters
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  # Providers

  def list_provider_adapters do
    Adapters.list_adapters()
  end

  def fetch_provider_by_id(id, %Subject{} = subject, opts \\ []) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_providers_permission()),
         true <- Validator.valid_uuid?(id) do
      {preload, _opts} = Keyword.pop(opts, :preload, [])

      Provider.Query.all()
      |> Provider.Query.by_id(id)
      |> Authorizer.for_subject(Provider, subject)
      |> Repo.fetch()
      |> case do
        {:ok, provider} ->
          {:ok, Repo.preload(provider, preload)}

        {:error, reason} ->
          {:error, reason}
      end
    else
      false -> {:error, :not_found}
      other -> other
    end
  end

  # used to during auth flow in the UI where Subject doesn't exist yet
  def fetch_active_provider_by_id(id) do
    if Validator.valid_uuid?(id) do
      Provider.Query.by_id(id)
      |> Provider.Query.not_disabled()
      |> Repo.fetch()
    else
      {:error, :not_found}
    end
  end

  @doc """
  This functions allows to fetch singleton providers like `email` or `token`.
  """
  def fetch_active_provider_by_adapter(adapter, %Subject{} = subject, opts \\ [])
      when adapter in [:email, :token, :userpass] do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_providers_permission()) do
      {preload, _opts} = Keyword.pop(opts, :preload, [])

      Provider.Query.by_adapter(adapter)
      |> Provider.Query.not_disabled()
      |> Authorizer.for_subject(Provider, subject)
      |> Repo.fetch()
      |> case do
        {:ok, provider} ->
          {:ok, Repo.preload(provider, preload)}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  def list_providers(%Subject{} = subject) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_providers_permission()) do
      Provider.Query.not_deleted()
      |> Authorizer.for_subject(Provider, subject)
      |> Repo.list()
    end
  end

  # used to build list of auth options for the UI
  def list_active_providers_for_account(%Accounts.Account{} = account) do
    Provider.Query.by_account_id(account.id)
    |> Provider.Query.not_disabled()
    |> Repo.list()
  end

  def list_providers_pending_token_refresh_by_adapter(adapter) do
    datetime_filter = DateTime.utc_now() |> DateTime.add(30, :minute)

    Provider.Query.by_adapter(adapter)
    |> Provider.Query.by_provisioner(:custom)
    |> Provider.Query.by_non_empty_refresh_token()
    |> Provider.Query.token_expires_at({:lt, datetime_filter})
    |> Provider.Query.not_disabled()
    |> Repo.list()
  end

  def list_providers_pending_sync_by_adapter(adapter) do
    Provider.Query.by_adapter(adapter)
    |> Provider.Query.by_provisioner(:custom)
    |> Provider.Query.only_ready_to_be_synced()
    |> Provider.Query.not_disabled()
    |> Repo.list()
  end

  def new_provider(%Accounts.Account{} = account, attrs \\ %{}) do
    Provider.Changeset.create(account, attrs)
    |> Adapters.provider_changeset()
  end

  def create_provider(%Accounts.Account{} = account, attrs, %Subject{} = subject) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_providers_permission()),
         :ok <- Accounts.ensure_has_access_to(subject, account),
         changeset =
           Provider.Changeset.create(account, attrs, subject)
           |> Adapters.provider_changeset(),
         {:ok, provider} <- Repo.insert(changeset) do
      Adapters.ensure_provisioned(provider)
    end
  end

  # used for testing and seeding the database
  @doc false
  def create_provider(%Accounts.Account{} = account, attrs) do
    changeset =
      Provider.Changeset.create(account, attrs)
      |> Adapters.provider_changeset()

    with {:ok, provider} <- Repo.insert(changeset) do
      Adapters.ensure_provisioned(provider)
    end
  end

  def change_provider(%Provider{} = provider, attrs \\ %{}) do
    Provider.Changeset.update(provider, attrs)
    |> Adapters.provider_changeset()
  end

  def update_provider(%Provider{} = provider, attrs, %Subject{} = subject) do
    mutate_provider(provider, subject, fn provider ->
      Provider.Changeset.update(provider, attrs)
      |> Adapters.provider_changeset()
    end)
  end

  def disable_provider(%Provider{} = provider, %Subject{} = subject) do
    mutate_provider(provider, subject, fn provider ->
      if other_active_providers_exist?(provider) do
        Provider.Changeset.disable_provider(provider)
      else
        :cant_disable_the_last_provider
      end
    end)
  end

  def enable_provider(%Provider{} = provider, %Subject{} = subject) do
    mutate_provider(provider, subject, &Provider.Changeset.enable_provider/1)
  end

  def delete_provider(%Provider{} = provider, %Subject{} = subject) do
    provider
    |> mutate_provider(subject, fn provider ->
      if other_active_providers_exist?(provider) do
        Provider.Changeset.delete_provider(provider)
      else
        :cant_delete_the_last_provider
      end
    end)
    |> case do
      {:ok, provider} ->
        Adapters.ensure_deprovisioned(provider)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp mutate_provider(%Provider{} = provider, %Subject{} = subject, callback)
       when is_function(callback, 1) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_providers_permission()) do
      Provider.Query.by_id(provider.id)
      |> Authorizer.for_subject(Provider, subject)
      |> Repo.fetch_and_update(with: callback)
    end
  end

  defp other_active_providers_exist?(%Provider{id: id, account_id: account_id}) do
    Provider.Query.by_id({:not, id})
    |> Provider.Query.by_adapter({:not_in, [:token]})
    |> Provider.Query.not_disabled()
    |> Provider.Query.by_account_id(account_id)
    |> Provider.Query.lock()
    |> Repo.exists?()
  end

  def fetch_provider_capabilities!(%Provider{} = provider) do
    Adapters.fetch_capabilities!(provider)
  end

  # Identities

  # used during magic link auth flow
  def fetch_active_identity_by_provider_and_identifier(
        %Provider{adapter: :email} = provider,
        provider_identifier,
        opts \\ []
      ) do
    {preload, _opts} = Keyword.pop(opts, :preload, [])

    Identity.Query.not_disabled()
    |> Identity.Query.by_provider_id(provider.id)
    |> Identity.Query.by_account_id(provider.account_id)
    |> Identity.Query.by_provider_identifier(provider_identifier)
    |> Repo.fetch()
    |> case do
      {:ok, identity} ->
        {:ok, Repo.preload(identity, preload)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_active_identity_by_id(id) do
    Identity.Query.by_id(id)
    |> Identity.Query.not_disabled()
    |> Repo.fetch()
  end

  def fetch_identity_by_id(id, %Subject{} = subject) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_identities_permission()),
         true <- Validator.valid_uuid?(id) do
      Identity.Query.by_id(id)
      |> Authorizer.for_subject(Identity, subject)
      |> Repo.fetch()
    else
      false -> {:error, :not_found}
      other -> other
    end
  end

  def fetch_identities_count_grouped_by_provider_id(%Subject{} = subject) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_identities_permission()) do
      {:ok, identities} =
        Identity.Query.group_by_provider_id()
        |> Authorizer.for_subject(Identity, subject)
        |> Repo.list()

      identities =
        Enum.reduce(identities, %{}, fn %{provider_id: id, count: count}, acc ->
          Map.put(acc, id, count)
        end)

      {:ok, identities}
    end
  end

  def sync_provider_identities_multi(%Provider{} = provider, attrs_list) do
    Identity.Sync.sync_provider_identities_multi(provider, attrs_list)
  end

  # used by IdP adapters
  def upsert_identity(%Actors.Actor{} = actor, %Provider{} = provider, attrs) do
    Identity.Changeset.create_identity(actor, provider, attrs)
    |> Adapters.identity_changeset(provider)
    |> Repo.insert(
      conflict_target:
        {:unsafe_fragment,
         ~s/(account_id, provider_id, provider_identifier) WHERE deleted_at IS NULL/},
      on_conflict: {:replace, [:provider_state]},
      returning: true
    )
  end

  def new_identity(%Actors.Actor{} = actor, %Provider{} = provider, attrs \\ %{}) do
    Identity.Changeset.create_identity(actor, provider, attrs)
    |> Adapters.identity_changeset(provider)
  end

  def create_identity(
        %Actors.Actor{} = actor,
        %Provider{} = provider,
        attrs,
        %Subject{} = subject
      ) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_identities_permission()) do
      create_identity(actor, provider, attrs)
    end
  end

  # used during sign up flow
  def create_identity(
        %Actors.Actor{account_id: account_id} = actor,
        %Provider{account_id: account_id} = provider,
        attrs
      ) do
    Identity.Changeset.create_identity(actor, provider, attrs)
    |> Adapters.identity_changeset(provider)
    |> Repo.insert()
  end

  def replace_identity(%Identity{} = identity, attrs, %Subject{} = subject) do
    required_permissions =
      {:one_of,
       [
         Authorizer.manage_identities_permission(),
         Authorizer.manage_own_identities_permission()
       ]}

    with :ok <- ensure_has_permissions(subject, required_permissions) do
      Ecto.Multi.new()
      |> Ecto.Multi.run(:identity, fn _repo, _effects_so_far ->
        Identity.Query.by_id(identity.id)
        |> Identity.Query.lock()
        |> Identity.Query.with_preloaded_assoc(:inner, :actor)
        |> Identity.Query.with_preloaded_assoc(:inner, :provider)
        |> Repo.fetch()
      end)
      |> Ecto.Multi.insert(:new_identity, fn %{identity: identity} ->
        Identity.Changeset.create_identity(identity.actor, identity.provider, attrs, subject)
        |> Adapters.identity_changeset(identity.provider)
      end)
      |> Ecto.Multi.update(:deleted_identity, fn %{identity: identity} ->
        Identity.Changeset.delete_identity(identity)
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{new_identity: identity}} ->
          {:ok, identity}

        {:error, _step, error_or_changeset, _effects_so_far} ->
          {:error, error_or_changeset}
      end
    end
  end

  def delete_identity(%Identity{created_by: :provider}, %Subject{}) do
    {:error, :cant_delete_synced_identity}
  end

  def delete_identity(%Identity{} = identity, %Subject{} = subject) do
    required_permissions =
      {:one_of,
       [
         Authorizer.manage_identities_permission(),
         Authorizer.manage_own_identities_permission()
       ]}

    with :ok <- ensure_has_permissions(subject, required_permissions) do
      Identity.Query.by_id(identity.id)
      |> Authorizer.for_subject(Identity, subject)
      |> Repo.fetch_and_update(with: &Identity.Changeset.delete_identity/1)
    end
  end

  def delete_actor_identities(%Actors.Actor{} = actor, %Subject{} = subject) do
    with :ok <- ensure_has_permissions(subject, Authorizer.manage_identities_permission()) do
      {_count, nil} =
        Identity.Query.by_actor_id(actor.id)
        |> Identity.Query.by_account_id(actor.account_id)
        |> Authorizer.for_subject(Identity, subject)
        |> Repo.update_all(set: [deleted_at: DateTime.utc_now(), provider_state: %{}])

      :ok
    end
  end

  def identity_disabled?(%{disabled_at: nil}), do: false
  def identity_disabled?(_identity), do: true

  def identity_deleted?(%{deleted_at: nil}), do: false
  def identity_deleted?(_identity), do: true

  # Sign Up / In / Off

  @doc """
  Sign In is an exchange of a secret (IdP token or username/password) for a token tied to it's original context.
  """
  def sign_in(
        %Provider{disabled_at: disabled_at},
        _id_or_provider_identifier,
        _secret,
        %Context{}
      )
      when not is_nil(disabled_at) do
    {:error, :unauthorized}
  end

  def sign_in(
        %Provider{deleted_at: deleted_at},
        _id_or_provider_identifier,
        _secret,
        %Context{}
      )
      when not is_nil(deleted_at) do
    {:error, :unauthorized}
  end

  def sign_in(%Provider{} = provider, id_or_provider_identifier, secret, %Context{} = context) do
    identity_queryable =
      Identity.Query.not_disabled()
      |> Identity.Query.by_account_id(provider.account_id)
      |> Identity.Query.by_provider_id(provider.id)
      |> Identity.Query.by_id_or_provider_identifier(id_or_provider_identifier)

    with {:ok, identity} <- Repo.fetch(identity_queryable),
         {:ok, identity, expires_at} <- Adapters.verify_secret(provider, identity, secret),
         {:ok, token} <- create_token(provider, identity, context, expires_at) do
      {:ok, Tokens.encode_token!(token)}
    else
      {:error, :not_found} -> {:error, :unauthorized}
      {:error, :invalid_secret} -> {:error, :unauthorized}
      {:error, :expired_secret} -> {:error, :unauthorized}
    end
  end

  def sign_in(%Provider{disabled_at: disabled_at}, _payload, %Context{})
      when not is_nil(disabled_at) do
    {:error, :unauthorized}
  end

  def sign_in(%Provider{deleted_at: deleted_at}, _payload, %Context{})
      when not is_nil(deleted_at) do
    {:error, :unauthorized}
  end

  def sign_in(%Provider{} = provider, payload, %Context{} = context) do
    with {:ok, identity, expires_at} <- Adapters.verify_and_update_identity(provider, payload),
         {:ok, token} <- create_token(provider, identity, context, expires_at) do
      {:ok, Tokens.encode_token!(token)}
    else
      {:error, :not_found} -> {:error, :unauthorized}
      {:error, :invalid} -> {:error, :unauthorized}
      {:error, :expired} -> {:error, :unauthorized}
    end
  end

  defp create_token(provider, identity, %{type: type} = context, expires_at)
       when type in [:browser, :client] do
    identity = Repo.preload(identity, :actor)
    expires_at = token_expires_at(identity.actor, context, expires_at)

    Tokens.create_token(%{
      type: context.type,
      secret: Domain.Crypto.random_token(32),
      account_id: provider.account_id,
      identity_id: identity.id,
      expires_at: expires_at,
      created_by_user_agent: context.user_agent,
      created_by_remote_ip: context.remote_ip
    })
  end

  # default expiration is used when IdP/adapter doesn't set the expiration date
  defp token_expires_at(%Actors.Actor{} = actor, %Context{} = context, nil) do
    default_session_duration_hours =
      @default_session_duration_hours
      |> Keyword.fetch!(context.type)
      |> Keyword.fetch!(actor.type)

    DateTime.utc_now() |> DateTime.add(default_session_duration_hours, :hour)
  end

  # For client tokens we extend the expiration to the default one
  # for the sake of user experience, because:
  #
  # - some of the IdPs don't allow to refresh the token without user interaction;
  # - some of the IdPs have short-lived hardcoded tokens
  #
  defp token_expires_at(%Actors.Actor{} = actor, %Context{type: :client}, _expires_at) do
    default_session_duration_hours =
      @default_session_duration_hours
      |> Keyword.fetch!(:client)
      |> Keyword.fetch!(actor.type)

    DateTime.utc_now() |> DateTime.add(default_session_duration_hours, :hour)
  end

  # when IdP sets the expiration we ensure it's not longer than the default session duration
  # to prevent extremely long-lived browser sessions
  defp token_expires_at(%Actors.Actor{} = actor, %Context{type: :browser}, expires_at) do
    max_session_duration_hours =
      @max_session_duration_hours
      |> Keyword.fetch!(:browser)
      |> Keyword.fetch!(actor.type)

    max_expires_at = DateTime.utc_now() |> DateTime.add(max_session_duration_hours, :hour)
    Enum.min([expires_at, max_expires_at], DateTime)
  end

  @doc """
  Revokes the Firezone token used by the given subject and,
  if IdP was used for Sign In, revokes the IdP token too by redirecting user to IdP logout endpoint.
  """
  def sign_out(%Subject{} = subject, redirect_url) do
    with {:ok, _token} <- Tokens.delete_token(subject.token) do
      identity = Repo.preload(subject.identity, :provider)
      Adapters.sign_out(identity.provider, identity, redirect_url)
    end
  end

  # Tokens

  def create_service_account_token(
        %Provider{adapter: :token} = provider,
        %Identity{} = identity,
        %Subject{} = subject
      ) do
    {:ok, expires_at, 0} = DateTime.from_iso8601(identity.provider_state["expires_at"])

    {:ok, token} =
      Tokens.create_token(
        %{
          type: :client,
          secret: Domain.Crypto.random_token(32),
          account_id: provider.account_id,
          identity_id: identity.id,
          expires_at: expires_at,
          created_by_user_agent: subject.context.user_agent,
          created_by_remote_ip: subject.context.remote_ip
        },
        subject
      )

    {:ok, Tokens.encode_token!(token)}
  end

  # Authentication

  def authenticate(account_id, encoded_token, %Context{} = context)
      when is_binary(encoded_token) do
    with {:ok, token} <- Tokens.use_token(account_id, encoded_token, context),
         :ok <- maybe_enforce_token_context(token, context),
  def sign_in(token, %Context{} = context) when is_binary(token) do
    with {:ok, identity, expires_at} <- verify_token(token, context.user_agent, context.remote_ip) do
      {:ok, build_subject(identity, expires_at, context)}
    else
         {:ok, identity} <- fetch_active_identity_by_id(token.identity_id) do
      {:ok, build_subject(token, identity, context)}
    else
      {:error, :invalid_or_expired_token} -> {:error, :unauthorized}
      {:error, :invalid_remote_ip} -> {:error, :unauthorized}
      {:error, :invalid_user_agent} -> {:error, :unauthorized}
      {:error, :not_found} -> {:error, :unauthorized}
    end
  end

  defp maybe_enforce_token_context(%Tokens.Token{} = token, %Context{type: :browser} = context) do
    cond do
      token.created_by_remote_ip.address != context.remote_ip -> {:error, :invalid_remote_ip}
      token.created_by_user_agent != context.user_agent -> {:error, :invalid_user_agent}
      true -> :ok
    end
  end

  defp maybe_enforce_token_context(%Tokens.Token{}, %Context{}) do
    :ok
  end

  # used in tests and seeds
  @doc false
  def build_subject(%Tokens.Token{} = token, %Identity{} = identity, %Context{} = context) do
    identity =
      identity
      |> Identity.Changeset.track_identity(context)
      |> Repo.update!()

    identity_with_preloads = Repo.preload(identity, [:account, :actor])
    permissions = fetch_type_permissions!(identity_with_preloads.actor.type)

    %Subject{
      identity: identity,
      actor: identity_with_preloads.actor,
      permissions: permissions,
      account: identity_with_preloads.account,
      expires_at: token.expires_at,
      context: context,
      token: token
    }
  end

  # Permissions

  def has_permission?(
        %Subject{permissions: granted_permissions},
        %Permission{} = required_permission
      ) do
    Enum.member?(granted_permissions, required_permission)
  end

  def has_permission?(%Subject{} = subject, {:one_of, required_permissions}) do
    Enum.any?(required_permissions, fn required_permission ->
      has_permission?(subject, required_permission)
    end)
  end

  def has_permissions?(%Subject{} = subject, required_permissions) do
    ensure_has_permissions(subject, required_permissions) == :ok
  end

  def fetch_type_permissions!(%Role{} = type),
    do: type.permissions

  def fetch_type_permissions!(type_name) when is_atom(type_name),
    do: type_name |> Roles.build() |> fetch_type_permissions!()

  # Authorization

  def ensure_type(%Subject{actor: %{type: type}}, type), do: :ok
  def ensure_type(%Subject{actor: %{}}, _type), do: {:error, :unauthorized}

  def ensure_has_access_to(%Subject{} = subject, %Provider{} = provider) do
    if subject.account.id == provider.account_id do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  def ensure_has_permissions(%Subject{} = subject, required_permissions) do
    with :ok <- ensure_permissions_are_not_expired(subject) do
      required_permissions
      |> List.wrap()
      |> Enum.reject(fn required_permission ->
        has_permission?(subject, required_permission)
      end)
      |> Enum.uniq()
      |> case do
        [] ->
          :ok

        missing_permissions ->
          {:error,
           {:unauthorized, reason: :missing_permissions, missing_permissions: missing_permissions}}
      end
    end
  end

  defp ensure_permissions_are_not_expired(%Subject{expires_at: nil}) do
    :ok
  end

  defp ensure_permissions_are_not_expired(%Subject{expires_at: expires_at}) do
    if DateTime.after?(expires_at, DateTime.utc_now()) do
      :ok
    else
      {:error, {:unauthorized, reason: :subject_expired}}
    end
  end

  def can_grant_role?(%Subject{} = subject, granted_role) do
    granted_permissions = fetch_type_permissions!(granted_role)
    MapSet.subset?(granted_permissions, subject.permissions)
  end
end
