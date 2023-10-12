defmodule Domain.Policies do
  alias Domain.{Repo, Validator, PubSub}
  alias Domain.Auth
  alias Domain.Policies.{Authorizer, Policy}

  def fetch_policy_by_id(id, %Auth.Subject{} = subject, opts \\ []) do
    {preload, _opts} = Keyword.pop(opts, :preload, [])

    required_permissions =
      {:one_of,
       [
         Authorizer.manage_policies_permission(),
         Authorizer.view_available_policies_permission()
       ]}

    with :ok <- Auth.ensure_has_permissions(subject, required_permissions),
         true <- Validator.valid_uuid?(id) do
      Policy.Query.all()
      |> Policy.Query.by_id(id)
      |> Authorizer.for_subject(subject)
      |> Repo.fetch()
      |> case do
        {:ok, policy} -> {:ok, Repo.preload(policy, preload)}
        {:error, reason} -> {:error, reason}
      end
    else
      false -> {:error, :not_found}
      other -> other
    end
  end

  def list_policies(%Auth.Subject{} = subject, opts \\ []) do
    {preload, _opts} = Keyword.pop(opts, :preload, [])

    required_permissions =
      {:one_of,
       [
         Authorizer.manage_policies_permission(),
         Authorizer.view_available_policies_permission()
       ]}

    with :ok <- Auth.ensure_has_permissions(subject, required_permissions) do
      {:ok, policies} =
        Policy.Query.not_deleted()
        |> Authorizer.for_subject(subject)
        |> Repo.list()

      {:ok, Repo.preload(policies, preload)}
    end
  end

  def create_policy(attrs, %Auth.Subject{} = subject) do
    required_permissions =
      {:one_of, [Authorizer.manage_policies_permission()]}

    with :ok <- Auth.ensure_has_permissions(subject, required_permissions) do
      Policy.Changeset.create(attrs, subject)
      |> Repo.insert()
      |> case do
        {:ok, policy} ->
          :ok = broadcast_events(:created, policy)
          {:ok, policy}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  def update_policy(%Policy{} = policy, attrs, %Auth.Subject{} = subject) do
    required_permissions =
      {:one_of, [Authorizer.manage_policies_permission()]}

    with :ok <- Auth.ensure_has_permissions(subject, required_permissions),
         :ok <- ensure_has_access_to(subject, policy) do
      Policy.Changeset.update(policy, attrs)
      |> Repo.update()
    end
  end

  def delete_policy(%Policy{} = policy, %Auth.Subject{} = subject) do
    required_permissions =
      {:one_of, [Authorizer.manage_policies_permission()]}

    with :ok <- Auth.ensure_has_permissions(subject, required_permissions) do
      Policy.Query.by_id(policy.id)
      |> Authorizer.for_subject(subject)
      |> Repo.fetch_and_update(with: &Policy.Changeset.delete/1)
      |> case do
        {:ok, policy} ->
          :ok = broadcast_events(:deleted, policy)
          {:ok, policy}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  def new_policy(attrs, %Auth.Subject{} = subject) do
    Policy.Changeset.create(attrs, subject)
  end

  def ensure_has_access_to(%Auth.Subject{} = subject, %Policy{} = policy) do
    if subject.account.id == policy.account_id do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  # defp broadcast_authorization_events(%Actors.Actor{} = actor) do
  #   payload = {:"resource_#{kind}", resource.id}

  #   for topic <- [
  #         "account_resources:#{resource.account_id}",
  #         "resources:#{resource.id}"
  #       ] do
  #     Phoenix.PubSub.broadcast(Domain.PubSub, topic, payload)
  #   end

  #   :ok
  # end

  defp broadcast_events(:created, %Policy{} = policy) do
    PubSub.broadcast(
      "actor_group_policies:#{policy.actor_group_id}",
      {:allow_access, policy.resource_id}
    )
  end

  defp broadcast_events(:deleted, %Policy{} = policy) do
    PubSub.broadcast(
      "actor_group_policies:#{policy.actor_group_id}",
      {:reject_access, policy.resource_id}
    )
  end

  def subscribe_for_events_for_actor_group(actor_group_id) do
    PubSub.subscribe("actor_group_policies:#{actor_group_id}")
  end

  def unsubscribe_from_events_for_actor_group(actor_group_id) do
    PubSub.unsubscribe("actor_group_policies:#{actor_group_id}")
  end

  # TODO: actor group events do not work when user is added or removed from group,
  # we really need to do it on per-actor basis :/
  # def subscribe_for_events_for_actor_group_and_resource(actor_group_id, resource_id) do
  #   PubSub.subscribe("policies:#{actor_group_id}-#{resource_id}")
  # end

  # def unsubscribe_from_events_for_actor_group_and_resource(actor_group_id, resource_id) do
  #   PubSub.unsubscribe("policies:#{actor_group_id}-#{resource_id}")
  # end
end

# {:allow_access, group_id, resource_id}
# {:reject_access, group_id, resource_id}

# {:resource_created, resource_id}
# {:resource_updated, resource_id}
# {:resource_deleted, resource_id}

# {:membership_created, actor_id, group_id}
# {:membership_deleted, actor_id, group_id}
