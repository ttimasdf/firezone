defmodule Web.SignInTest do
  use Web.ConnCase, async: true

  test "renders active providers on the page", %{conn: conn} do
    Domain.Config.put_env_override(:outbound_email_adapter_configured?, true)

    account = Fixtures.Accounts.create_account()

    email_provider = Fixtures.Auth.create_email_provider(account: account)

    {:ok, _lv, html} = live(conn, ~p"/#{account}")

    assert html =~ "Sign in with email"
    refute html =~ "Sign in with username and password"

    userpass_provider = Fixtures.Auth.create_userpass_provider(account: account)

    {:ok, _lv, html} = live(conn, ~p"/#{account}")

    assert html =~ "Sign in with username and password"
    refute html =~ "Vault"

    Fixtures.Auth.start_and_create_openid_connect_provider(name: "Vault", account: account)

    {:ok, _lv, html} = live(conn, ~p"/#{account}")

    assert html =~ "Vault"

    identity =
      Fixtures.Auth.create_identity(
        actor: [type: :account_admin_user],
        account: account,
        provider: email_provider
      )

    subject = Fixtures.Auth.create_subject(identity: identity)

    {:ok, _provider} = Domain.Auth.disable_provider(userpass_provider, subject)
    {:ok, _lv, html} = live(conn, ~p"/#{account}")
    refute html =~ "Sign in with username and password"

    {:ok, _provider} = Domain.Auth.delete_provider(email_provider, subject)
    {:ok, _lv, html} = live(conn, ~p"/#{account}")
    refute html =~ "Sign in with email"

    assert html =~ "Vault"
    assert html =~ ~s|Meant to sign in from a client instead?|
  end

  test "keeps client auth params", %{conn: conn} do
    Domain.Config.put_env_override(:outbound_email_adapter_configured?, true)
    account = Fixtures.Accounts.create_account()
    Fixtures.Auth.create_email_provider(account: account)

    {:ok, _lv, html} = live(conn, ~p"/#{account}?as=client&nonce=NONCE&state=STATE")

    assert html =~ ~s|value="NONCE"|
    assert html =~ ~s|value="STATE"|
    assert html =~ ~s|value="client"|
  end

  test "hides client sign in suggestion when client is used", %{conn: conn} do
    Domain.Config.put_env_override(:outbound_email_adapter_configured?, true)
    account = Fixtures.Accounts.create_account()
    Fixtures.Auth.create_email_provider(account: account)

    {:ok, _lv, html} = live(conn, ~p"/#{account}?as=client")

    refute html =~ ~s|Meant to sign in from a client instead?|
  end
end
