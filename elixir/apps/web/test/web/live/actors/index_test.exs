defmodule Web.Live.Actors.IndexTest do
  use Web.ConnCase, async: true

  setup do
    account = Fixtures.Accounts.create_account()
    identity = Fixtures.Auth.create_identity(account: account, actor: [type: :account_admin_user])

    %{
      account: account,
      identity: identity
    }
  end

  test "redirects to sign in page for unauthorized user", %{account: account, conn: conn} do
    path = ~p"/#{account}/actors"

    assert live(conn, path) ==
             {:error,
              {:redirect,
               %{
                 to: ~p"/#{account}?#{%{redirect_to: path}}",
                 flash: %{"error" => "You must log in to access this page."}
               }}}
  end

  test "renders breadcrumbs item", %{
    account: account,
    identity: identity,
    conn: conn
  } do
    {:ok, _lv, html} =
      conn
      |> authorize_conn(identity)
      |> live(~p"/#{account}/actors")

    assert item = Floki.find(html, "[aria-label='Breadcrumb']")
    breadcrumbs = String.trim(Floki.text(item))
    assert breadcrumbs =~ "Actors"
  end

  test "renders add actor button", %{
    account: account,
    identity: identity,
    conn: conn
  } do
    {:ok, _lv, html} =
      conn
      |> authorize_conn(identity)
      |> live(~p"/#{account}/actors")

    assert button = Floki.find(html, "a[href='/#{account.slug}/actors/new']")
    assert Floki.text(button) =~ "Add Actor"
  end

  test "renders actors table", %{
    account: account,
    identity: identity,
    conn: conn
  } do
    admin_actor = Fixtures.Actors.create_actor(account: account, type: :account_admin_user)
    Fixtures.Actors.create_membership(account: account, actor: admin_actor)
    admin_actor = Repo.preload(admin_actor, identities: [:provider], groups: [])

    user_actor = Fixtures.Actors.create_actor(account: account, type: :account_user)
    Fixtures.Actors.create_membership(account: account, actor: user_actor)
    Fixtures.Actors.create_membership(account: account, actor: user_actor)
    Fixtures.Actors.create_membership(account: account, actor: user_actor)
    user_actor = Repo.preload(user_actor, identities: [:provider], groups: [])

    service_account_actor = Fixtures.Actors.create_actor(account: account, type: :service_account)
    Fixtures.Actors.create_membership(account: account, actor: service_account_actor)

    service_account_actor =
      Repo.preload(service_account_actor, identities: [:provider], groups: [])

    {:ok, lv, _html} =
      conn
      |> authorize_conn(identity)
      |> live(~p"/#{account}/actors")

    rows =
      lv
      |> element("#actors")
      |> render()
      |> table_to_map()

    for {actor, name} <- [
          {admin_actor, "#{admin_actor.name} (admin)"},
          {user_actor, user_actor.name},
          {service_account_actor, "#{service_account_actor.name} (service account)"}
        ] do
      with_table_row(rows, "name", name, fn row ->
        for identity <- actor.identities do
          assert row["identifiers"] =~ identity.provider.name
          assert row["identifiers"] =~ identity.provider_identifier
        end

        for group <- actor.groups do
          assert row["groups"] =~ group.name
        end

        assert row["last signed in"] == "never"
      end)
    end
  end

  test "renders last signed date", %{
    account: account,
    identity: identity,
    conn: conn
  } do
    actor = Fixtures.Actors.create_actor(account: account, type: :account_user)

    Fixtures.Auth.create_identity(account: account, actor: actor)
    |> Ecto.Changeset.change(last_seen_at: DateTime.utc_now() |> DateTime.add(-24, :hour))
    |> Repo.update!()

    Fixtures.Auth.create_identity(account: account, actor: actor)
    |> Ecto.Changeset.change(last_seen_at: DateTime.utc_now() |> DateTime.add(-1, :hour))
    |> Repo.update!()

    Fixtures.Auth.create_identity(account: account, actor: actor)
    |> Ecto.Changeset.change(last_seen_at: DateTime.utc_now() |> DateTime.add(-8, :hour))
    |> Repo.update!()

    {:ok, lv, _html} =
      conn
      |> authorize_conn(identity)
      |> live(~p"/#{account}/actors")

    lv
    |> element("#actors")
    |> render()
    |> table_to_map()
    |> with_table_row("name", actor.name, fn row ->
      assert row["last signed in"] == "1 hour ago"
    end)
  end
end
