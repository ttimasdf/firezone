defmodule API.Client.Channel do
  use API, :channel
  alias API.Client.Views
  alias Domain.Instrumentation
  alias Domain.{Actors, Clients, Resources, Policies, Gateways, Relays, Flows}
  require Logger
  require OpenTelemetry.Tracer

  def broadcast(%Clients.Client{} = client, payload) do
    broadcast(client.id, payload)
  end

  def broadcast(client_id, payload) do
    Logger.debug("Client message is being dispatched", client_id: client_id)
    Domain.PubSub.broadcast("client:#{client_id}", payload)
  end

  @impl true
  def join("client", _payload, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.join" do
      opentelemetry_ctx = OpenTelemetry.Ctx.get_current()
      opentelemetry_span_ctx = OpenTelemetry.Tracer.current_span_ctx()

      expires_in =
        DateTime.diff(socket.assigns.subject.expires_at, DateTime.utc_now(), :millisecond)

      if expires_in > 0 do
        Process.send_after(self(), :token_expired, expires_in)
        send(self(), {:after_join, {opentelemetry_ctx, opentelemetry_span_ctx}})

        socket =
          assign(socket,
            opentelemetry_ctx: opentelemetry_ctx,
            opentelemetry_span_ctx: opentelemetry_span_ctx
          )

        {:ok, socket}
      else
        {:error, %{"reason" => "token_expired"}}
      end
    end
  end

  @impl true
  def handle_info({:after_join, {opentelemetry_ctx, opentelemetry_span_ctx}}, socket) do
    OpenTelemetry.Ctx.attach(opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.after_join" do
      {:ok, resources} = Resources.list_authorized_resources(socket.assigns.subject)
      {:ok, actor_group_ids} = Actors.list_actor_group_ids(socket.assigns.subject.actor)

      :ok = Domain.PubSub.subscribe("client:#{socket.assigns.client.id}")
      :ok = Resources.subscribe_for_resource_events_in_account(socket.assigns.client.account_id)
      :ok = Enum.each(actor_group_ids, &Policies.subscribe_for_events_for_actor_group(&1))
      :ok = Clients.connect_client(socket.assigns.client)

      :ok =
        push(socket, "init", %{
          resources: Views.Resource.render_many(resources),
          interface: Views.Interface.render(socket.assigns.client)
        })

      {:noreply, socket}
    end
  end

  def handle_info(:token_expired, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.token_expired" do
      push(socket, "disconnect", %{"reason" => "token_expired"})
      {:stop, {:shutdown, :token_expired}, socket}
    end
  end

  def handle_info(
        {:ice_candidates, gateway_id, candidates, {opentelemetry_ctx, opentelemetry_span_ctx}},
        socket
      ) do
    OpenTelemetry.Ctx.attach(opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.ice_candidates",
      attributes: %{
        gateway_id: gateway_id,
        candidates_length: length(candidates)
      } do
      push(socket, "ice_candidates", %{
        gateway_id: gateway_id,
        candidates: candidates
      })

      {:noreply, socket}
    end
  end

  # This message is sent by the gateway when it is ready
  # to accept the connection from the client
  def handle_info(
        {:connect, socket_ref, resource_id, gateway_public_key, rtc_session_description,
         {opentelemetry_ctx, opentelemetry_span_ctx}},
        socket
      ) do
    OpenTelemetry.Ctx.attach(opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.connect", attributes: %{resource_id: resource_id} do
      reply(
        socket_ref,
        {:ok,
         %{
           resource_id: resource_id,
           persistent_keepalive: 25,
           gateway_public_key: gateway_public_key,
           gateway_rtc_session_description: rtc_session_description
         }}
      )

      {:noreply, socket}
    end
  end

  def handle_info({:resource_created, resource_id}, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.resource_created", attributes:  %{resource_id: resource_id} do
      with {:ok, resource} <-
             Resources.fetch_and_authorize_resource_by_id(resource_id, socket.assigns.subject) do
        push(socket, "resource_created", Views.Resource.render(resource))
      end

      {:noreply, socket}
    end
  end

  def handle_info({:resource_updated, resource_id}, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)


    OpenTelemetry.Tracer.with_span "client.resource_updated", attributes:  %{resource_id: resource_id} do
      with {:ok, resource} <-
             Resources.fetch_and_authorize_resource_by_id(resource_id, socket.assigns.subject) do
        push(socket, "resource_updated", Views.Resource.render(resource))
      end

      {:noreply, socket}
    end
  end

  def handle_info({:resource_deleted, resource_id}, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)


    OpenTelemetry.Tracer.with_span "client.resource_deleted", attributes: %{resource_id: resource_id} do
      push(socket, "resource_deleted", resource_id)
      {:noreply, socket}
    end
  end

  # TODO: this is not enough, we also need to react on actor group memberships changes

  # This message is received when there is a policy created
  # allowing access to a resource by a client actor group
  def handle_info({:allow_access, resource_id}, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.allow_access", %{resource_id: resource_id} do
      with {:ok, resource} <-
             Resources.fetch_and_authorize_resource_by_id(resource_id, socket.assigns.subject) do
        push(socket, "resource_created", Views.Resource.render(resource))
      end

      {:noreply, socket}
    end
  end

  # This message is received when the policy
  # allowing access to a resource by a client actor group is deleted
  def handle_info({:reject_access, resource_id}, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.reject_access", %{resource_id: resource_id} do
      # There can be other policies allowing the access so we try to re-authorize the client first,
      # TODO: this will not close previous flow and create a new one,
      # which can be confusing during investigations
      case Resources.fetch_and_authorize_resource_by_id(resource_id, socket.assigns.subject) do
        {:ok, resource} -> push(socket, "resource_updated", Views.Resource.render(resource))
        {:error, _reason} -> push(socket, "resource_deleted", resource_id)
      end

      {:noreply, socket}
    end
  end

  def handle_in("create_log_sink", _attrs, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.create_log_sink" do
      case Instrumentation.create_remote_log_sink(socket.assigns.client) do
        {:ok, signed_url} -> {:reply, {:ok, signed_url}, socket}
        {:error, :disabled} -> {:reply, {:error, :disabled}, socket}
      end
    end
  end

  @impl true
  def handle_in("prepare_connection", %{"resource_id" => resource_id} = attrs, socket) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.prepare_connection", attributes: attrs do
      connected_gateway_ids = Map.get(attrs, "connected_gateway_ids", [])

      with {:ok, resource} <-
             Resources.fetch_and_authorize_resource_by_id(resource_id, socket.assigns.subject),
           {:ok, [_ | _] = gateways} <-
             Gateways.list_connected_gateways_for_resource(resource, preload: :group),
           gateway_groups = Enum.map(gateways, & &1.group),
           {relay_hosting_type, relay_connection_type} =
             Gateways.relay_strategy(gateway_groups),
           {:ok, [_ | _] = relays} <-
             Relays.list_connected_relays_for_resource(resource, relay_hosting_type) do
        location = {
          socket.assigns.client.last_seen_remote_ip_location_lat,
          socket.assigns.client.last_seen_remote_ip_location_lon
        }

        OpenTelemetry.Tracer.set_attribute(:relays_length, length(relays))
        OpenTelemetry.Tracer.set_attribute(:gateways_length, length(gateways))
        OpenTelemetry.Tracer.set_attribute(:relay_hosting_type, relay_hosting_type)
        OpenTelemetry.Tracer.set_attribute(:relay_connection_type, relay_connection_type)

        relays = Relays.load_balance_relays(location, relays)
        gateway = Gateways.load_balance_gateways(location, gateways, connected_gateway_ids)

        reply =
          {:ok,
           %{
             relays:
               Views.Relay.render_many(
                 relays,
                 socket.assigns.subject.expires_at,
                 relay_connection_type
               ),
             resource_id: resource_id,
             gateway_id: gateway.id,
             gateway_remote_ip: gateway.last_seen_remote_ip
           }}

        {:reply, reply, socket}
      else
        {:ok, []} ->
          OpenTelemetry.Tracer.set_status(:error, "offline")
          {:reply, {:error, :offline}, socket}

        {:error, :not_found} ->
          OpenTelemetry.Tracer.set_status(:error, "not_found")
          {:reply, {:error, :not_found}, socket}
      end
    end
  end

  # This message is sent by the client when it already has connection to a gateway,
  # but wants to connect to a new resource
  def handle_in(
        "reuse_connection",
        %{
          "gateway_id" => gateway_id,
          "resource_id" => resource_id
        } = attrs,
        socket
      ) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.reuse_connection", attributes: attrs do
      with {:ok, gateway} <- Gateways.fetch_gateway_by_id(gateway_id, socket.assigns.subject),
           {:ok, resource, flow} <-
             Flows.authorize_flow(
               socket.assigns.client,
               gateway,
               resource_id,
               socket.assigns.subject
             ),
           true <- Gateways.gateway_can_connect_to_resource?(gateway, resource) do
        opentelemetry_ctx = OpenTelemetry.Ctx.get_current()
        opentelemetry_span_ctx = OpenTelemetry.Tracer.current_span_ctx()

        :ok =
          API.Gateway.Channel.broadcast(
            gateway,
            {:allow_access,
             %{
               client_id: socket.assigns.client.id,
               resource_id: resource.id,
               flow_id: flow.id,
               authorization_expires_at: socket.assigns.subject.expires_at
             }, {opentelemetry_ctx, opentelemetry_span_ctx}}
          )

        {:noreply, socket}
      else
        {:error, :not_found} ->
          OpenTelemetry.Tracer.set_status(:error, "not_found")
          {:reply, {:error, :not_found}, socket}

        false ->
          OpenTelemetry.Tracer.set_status(:error, "offline")
          {:reply, {:error, :offline}, socket}
      end
    end
  end

  # This message is sent by the client when it wants to connect to a new gateway
  def handle_in(
        "request_connection",
        %{
          "gateway_id" => gateway_id,
          "resource_id" => resource_id,
          "client_rtc_session_description" => client_rtc_session_description,
          "client_preshared_key" => preshared_key
        },
        socket
      ) do
    ctx_attrs = %{gateway_id: gateway_id, resource_id: resource_id}
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.request_connection", attributes: ctx_attrs do
      with {:ok, gateway} <- Gateways.fetch_gateway_by_id(gateway_id, socket.assigns.subject),
           {:ok, resource, flow} <-
             Flows.authorize_flow(
               socket.assigns.client,
               gateway,
               resource_id,
               socket.assigns.subject
             ),
           true <- Gateways.gateway_can_connect_to_resource?(gateway, resource) do
        opentelemetry_ctx = OpenTelemetry.Ctx.get_current()
        opentelemetry_span_ctx = OpenTelemetry.Tracer.current_span_ctx()

        :ok =
          API.Gateway.Channel.broadcast(
            gateway,
            {:request_connection, {self(), socket_ref(socket)},
             %{
               client_id: socket.assigns.client.id,
               resource_id: resource.id,
               flow_id: flow.id,
               authorization_expires_at: socket.assigns.subject.expires_at,
               client_rtc_session_description: client_rtc_session_description,
               client_preshared_key: preshared_key
             }, {opentelemetry_ctx, opentelemetry_span_ctx}}
          )

        {:noreply, socket}
      else
        {:error, :not_found} ->
          OpenTelemetry.Tracer.set_status(:error, "not_found")
          {:reply, {:error, :not_found}, socket}

        false ->
          OpenTelemetry.Tracer.set_status(:error, "offline")
          {:reply, {:error, :offline}, socket}
      end
    end
  end

  def handle_in(
        "broadcast_ice_candidates",
        %{"candidates" => candidates, "gateway_ids" => gateway_ids},
        socket
      ) do
    OpenTelemetry.Ctx.attach(socket.assigns.opentelemetry_ctx)
    OpenTelemetry.Tracer.set_current_span(socket.assigns.opentelemetry_span_ctx)

    OpenTelemetry.Tracer.with_span "client.broadcast_ice_candidates" do
      opentelemetry_ctx = OpenTelemetry.Ctx.get_current()
      opentelemetry_span_ctx = OpenTelemetry.Tracer.current_span_ctx()

      :ok =
        Enum.each(gateway_ids, fn gateway_id ->
          API.Gateway.Channel.broadcast(
            gateway_id,
            {:ice_candidates, socket.assigns.client.id, candidates,
             {opentelemetry_ctx, opentelemetry_span_ctx}}
          )
        end)

      {:noreply, socket}
    end
  end
end
