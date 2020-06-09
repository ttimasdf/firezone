defmodule FgHttp.Rules do
  @moduledoc """
  The Rules context.
  """

  import Ecto.Query, warn: false
  alias FgHttp.Repo

  alias FgHttp.Rules.Rule

  def list_rules(device_id) do
    Repo.all(from r in Rule, where: r.device_id == ^device_id)
  end

  def list_rules do
    Repo.all(Rule)
  end

  def get_rule!(id), do: Repo.get!(Rule, id)

  def create_rule(attrs \\ %{}) do
    %Rule{}
    |> Rule.changeset(attrs)
    |> Repo.insert()
  end

  def update_rule(%Rule{} = rule, attrs) do
    rule
    |> Rule.changeset(attrs)
    |> Repo.update()
  end

  def delete_rule(%Rule{} = rule) do
    Repo.delete(rule)
  end

  def change_rule(%Rule{} = rule) do
    Rule.changeset(rule, %{})
  end
end
