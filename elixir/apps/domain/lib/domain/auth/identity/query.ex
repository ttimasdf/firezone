defmodule Domain.Auth.Identity.Query do
  use Domain, :query

  def all do
    from(identities in Domain.Auth.Identity, as: :identities)
  end

  def not_deleted do
    all()
    |> where([identities: identities], is_nil(identities.deleted_at))
  end

  def not_disabled(queryable \\ not_deleted()) do
    queryable
    |> with_assoc(:inner, :actor)
    |> where([actor: actor], is_nil(actor.deleted_at))
    |> where([actor: actor], is_nil(actor.disabled_at))
    |> with_assoc(:inner, :provider)
    |> where([provider: provider], is_nil(provider.deleted_at))
    |> where([provider: provider], is_nil(provider.disabled_at))
  end

  def by_id(queryable \\ not_deleted(), id)

  def by_id(queryable, {:not, id}) do
    where(queryable, [identities: identities], identities.id != ^id)
  end

  def by_id(queryable, id) do
    where(queryable, [identities: identities], identities.id == ^id)
  end

  def by_account_id(queryable \\ not_deleted(), account_id) do
    where(queryable, [identities: identities], identities.account_id == ^account_id)
  end

  def by_actor_id(queryable \\ not_deleted(), actor_id) do
    where(queryable, [identities: identities], identities.actor_id == ^actor_id)
  end

  def by_provider_id(queryable \\ not_deleted(), provider_id) do
    queryable
    |> where([identities: identities], identities.provider_id == ^provider_id)
  end

  def by_adapter(queryable \\ not_deleted(), adapter) do
    where(queryable, [identities: identities], identities.adapter == ^adapter)
  end

  def by_provider_identifier(queryable \\ not_deleted(), provider_identifier)

  def by_provider_identifier(queryable, {:in, provider_identifiers}) do
    where(
      queryable,
      [identities: identities],
      identities.provider_identifier in ^provider_identifiers
    )
  end

  def by_provider_identifier(queryable, provider_identifier) do
    where(
      queryable,
      [identities: identities],
      identities.provider_identifier == ^provider_identifier
    )
  end

  def by_id_or_provider_identifier(queryable \\ not_deleted(), id_or_provider_identifier) do
    if Domain.Validator.valid_uuid?(id_or_provider_identifier) do
      where(
        queryable,
        [identities: identities],
        identities.provider_identifier == ^id_or_provider_identifier or
          identities.id == ^id_or_provider_identifier
      )
    else
      by_provider_identifier(queryable, id_or_provider_identifier)
    end
  end

  def lock(queryable \\ not_deleted()) do
    lock(queryable, "FOR UPDATE")
  end

  def group_by_provider_id(queryable \\ not_deleted()) do
    queryable
    |> group_by([identities: identities], identities.provider_id)
    |> select([identities: identities], %{
      provider_id: identities.provider_id,
      count: count(identities.id)
    })
  end

  def with_preloaded_assoc(queryable \\ not_deleted(), type \\ :left, assoc) do
    queryable
    |> with_assoc(type, assoc)
    |> preload([{^assoc, assoc}], [{^assoc, assoc}])
  end

  def with_assoc(queryable \\ not_deleted(), type \\ :left, assoc) do
    with_named_binding(queryable, assoc, fn query, binding ->
      join(query, type, [identities: identities], a in assoc(identities, ^binding), as: ^binding)
    end)
  end
end
