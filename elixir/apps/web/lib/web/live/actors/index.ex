defmodule Web.Actors.Index do
  use Web, :live_view
  import Web.Actors.Components
  alias Domain.Auth
  alias Domain.Actors

  def mount(_params, _session, socket) do
    with {:ok, actors} <-
           Actors.list_actors(socket.assigns.subject, preload: [identities: :provider]),
         {:ok, actor_groups} <- Actors.peek_actor_groups(actors, 3, socket.assigns.subject),
         {:ok, providers} <- Auth.list_providers(socket.assigns.subject) do
      socket =
        assign(socket,
          actors: actors,
          actor_groups: actor_groups,
          providers_by_id: Map.new(providers, &{&1.id, &1}),
          page_title: "Actors"
        )

      {:ok, socket}
    else
      {:error, _reason} -> raise Web.LiveErrors.NotFoundError
    end
  end

  def render(assigns) do
    ~H"""
    <.breadcrumbs account={@account}>
      <.breadcrumb path={~p"/#{@account}/actors"}><%= @page_title %></.breadcrumb>
    </.breadcrumbs>

    <.section>
      <:title><%= @page_title %></:title>

      <:action>
        <.add_button navigate={~p"/#{@account}/actors/new"}>
          Add Actor
        </.add_button>
      </:action>
      <:help>
        Actors are the people and services that can access your resources.
      </:help>
      <:content>
        <.table id="actors" rows={@actors} row_id={&"user-#{&1.id}"}>
          <:col :let={actor} label="name" sortable="false">
            <.actor_name_and_role account={@account} actor={actor} />
          </:col>

          <:col :let={actor} label="identifiers" sortable="false">
            <div class="flex flex-wrap gap-y-2">
              <.identity_identifier
                :for={identity <- actor.identities}
                account={@account}
                identity={identity}
              />
            </div>
          </:col>

          <:col :let={actor} label="groups" sortable="false">
            <.peek peek={@actor_groups[actor.id]}>
              <:empty>
                None
              </:empty>

              <:item :let={group}>
                <.group
                  account={@account}
                  group={%{group | provider: Map.get(@providers_by_id, group.provider_id)}}
                />
              </:item>

              <:tail :let={count}>
                <span class="inline-block whitespace-nowrap">
                  and <%= count %> more.
                </span>
              </:tail>
            </.peek>
          </:col>

          <:col :let={actor} label="last signed in" sortable="false">
            <.relative_datetime datetime={last_seen_at(actor.identities)} />
          </:col>
          <:empty>
            <div class="flex justify-center text-center text-neutral-500 p-4">
              <div class="w-auto">
                <div class="pb-4">
                  No actors to display
                </div>
                <.add_button navigate={~p"/#{@account}/actors/new"}>
                  Add Actor
                </.add_button>
              </div>
            </div>
          </:empty>
        </.table>
      </:content>
    </.section>
    """
  end

  defp last_seen_at(identities) do
    identities
    |> Enum.reject(&is_nil(&1.last_seen_at))
    |> Enum.max_by(& &1.last_seen_at, DateTime, fn -> nil end)
    |> case do
      nil -> nil
      identity -> identity.last_seen_at
    end
  end
end
