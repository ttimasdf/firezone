defmodule Web.Groups.Index do
  use Web, :live_view
  import Web.Groups.Components
  alias Domain.Actors

  def mount(_params, _session, socket) do
    with {:ok, groups} <-
           Actors.list_groups(socket.assigns.subject,
             preload: [:provider, created_by_identity: [:actor]]
           ),
         {:ok, group_actors} <- Actors.peek_group_actors(groups, 3, socket.assigns.subject) do
      socket =
        assign(socket,
          page_title: "Groups",
          groups: groups,
          group_actors: group_actors
        )

      {:ok, socket}
    else
      {:error, _reason} -> raise Web.LiveErrors.NotFoundError
    end
  end

  def render(assigns) do
    ~H"""
    <.breadcrumbs account={@account}>
      <.breadcrumb path={~p"/#{@account}/groups"}><%= @page_title %></.breadcrumb>
    </.breadcrumbs>

    <.section>
      <:title>
        Groups
      </:title>
      <:action>
        <.add_button navigate={~p"/#{@account}/groups/new"}>
          Add Group
        </.add_button>
      </:action>
      <:content>
        <div class="bg-white overflow-hidden">
          <!--<.resource_filter />-->
          <.table id="groups" rows={@groups} row_id={&"user-#{&1.id}"}>
            <:col :let={group} label="NAME" sortable="false">
              <.link
                navigate={~p"/#{@account}/groups/#{group.id}"}
                class={["font-medium", link_style()]}
              >
                <%= group.name %>
              </.link>

              <span :if={Actors.group_deleted?(group)} class="text-xs text-neutral-100">
                (deleted)
              </span>
            </:col>
            <:col :let={group} label="ACTORS" sortable="false">
              <.peek peek={Map.fetch!(@group_actors, group.id)}>
                <:empty>
                  None
                </:empty>

                <:separator>
                  <span class="pr-1">,</span>
                </:separator>

                <:item :let={actor}>
                  <.link
                    navigate={~p"/#{@account}/actors/#{actor}"}
                    class={["font-medium", link_style()]}
                  >
                    <%= actor.name %>
                  </.link>
                </:item>

                <:tail :let={count}>
                  <span class="pl-1">
                    and <%= count %> more.
                  </span>
                </:tail>
              </.peek>
            </:col>
            <:col :let={group} label="SOURCE" sortable="false">
              <.source account={@account} group={group} />
            </:col>
            <:empty>
              <div class="flex justify-center text-center text-neutral-500 p-4">
                <div class="w-auto">
                  <div class="pb-4">
                    No groups to display
                  </div>
                  <.add_button navigate={~p"/#{@account}/groups/new"}>
                    Add Group
                  </.add_button>
                  <span class="font-semibold px-2 mb-4">or</span>
                  <.add_button navigate={~p"/#{@account}/settings/identity_providers"}>
                    Sync Groups from IdP
                  </.add_button>
                </div>
              </div>
            </:empty>
          </.table>
          <!--<.paginator page={3} total_pages={100} collection_base_path={~p"/#{@account}/groups"} />-->
        </div>
      </:content>
    </.section>
    """
  end
end
