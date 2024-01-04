defmodule Domain.Validator do
  @doc """
  A set of changeset helpers and schema extensions to simplify our changesets and make validation more reliable.
  """
  import Ecto.Changeset

  def changed?(changeset, field) do
    Map.has_key?(changeset.changes, field)
  end

  def empty?(changeset, field) do
    case fetch_field(changeset, field) do
      :error -> true
      {_data_or_changes, nil} -> true
      {_data_or_changes, _value} -> false
    end
  end

  def has_errors?(changeset, field) do
    Keyword.has_key?(changeset.errors, field)
  end

  def validate_email(changeset, field) do
    changeset
    |> validate_format(field, ~r/^[^\s]+@[^\s]+$/, message: "is an invalid email address")
    |> validate_length(field, max: 160)
  end

  def validate_does_not_contain(changeset, field, substring, opts \\ []) do
    validate_change(changeset, field, fn _current_field, value ->
      if String.contains?(value, substring) do
        message = Keyword.get(opts, :message, "can not contain #{inspect(substring)}")
        [{field, message}]
      else
        []
      end
    end)
  end

  def validate_does_not_end_with(changeset, field, suffix, opts \\ []) do
    validate_change(changeset, field, fn _current_field, value ->
      if String.ends_with?(value, suffix) do
        message = Keyword.get(opts, :message, "can not end with #{inspect(suffix)}")
        [{field, message}]
      else
        []
      end
    end)
  end

  def validate_uri(changeset, field, opts \\ []) when is_atom(field) do
    valid_schemes = Keyword.get(opts, :schemes, ~w[http https])
    require_trailing_slash? = Keyword.get(opts, :require_trailing_slash, false)

    validate_change(changeset, field, fn _current_field, value ->
      case URI.new(value) do
        {:ok, %URI{} = uri} ->
          cond do
            uri.host == nil or uri.host == "" ->
              [{field, "does not contain a scheme or a host"}]

            uri.scheme == nil ->
              [{field, "does not contain a scheme"}]

            uri.scheme not in valid_schemes ->
              [{field, "only #{Enum.join(valid_schemes, ", ")} schemes are supported"}]

            require_trailing_slash? and not is_nil(uri.path) and
                not String.ends_with?(uri.path, "/") ->
              [{field, "does not end with a trailing slash"}]

            true ->
              []
          end

        {:error, part} ->
          [{field, "is invalid. Error at #{part}"}]
      end
    end)
  end

  def normalize_url(changeset, field) do
    with {:ok, value} <- fetch_change(changeset, field),
         false <- has_errors?(changeset, field) do
      uri = URI.parse(value)
      scheme = uri.scheme || "https"
      port = URI.default_port(scheme)
      path = maybe_add_trailing_slash(uri.path || "/")
      uri = %{uri | scheme: scheme, port: port, path: path}
      uri_string = URI.to_string(uri)
      put_change(changeset, field, uri_string)
    else
      _ -> changeset
    end
  end

  defp maybe_add_trailing_slash(value) do
    if String.ends_with?(value, "/") do
      value
    else
      value <> "/"
    end
  end

  def validate_one_of(changeset, field, validators) do
    validate_change(changeset, field, fn current_field, _value ->
      orig_errors = Enum.filter(changeset.errors, &(elem(&1, 0) == current_field))

      Enum.reduce_while(validators, [], fn validator, errors ->
        validated_cs = validator.(changeset, current_field)

        new_errors =
          Enum.filter(validated_cs.errors, &(elem(&1, 0) == current_field)) -- orig_errors

        if Enum.empty?(new_errors) do
          {:halt, new_errors}
        else
          {:cont, new_errors ++ errors}
        end
      end)
    end)
  end

  def validate_no_duplicates(changeset, field) when is_atom(field) do
    validate_change(changeset, field, fn _current_field, list when is_list(list) ->
      list
      |> Enum.reduce_while({true, MapSet.new()}, fn value, {true, acc} ->
        if MapSet.member?(acc, value) do
          {:halt, {false, acc}}
        else
          {:cont, {true, MapSet.put(acc, value)}}
        end
      end)
      |> case do
        {true, _map_set} -> []
        {false, _map_set} -> [{field, "should not contain duplicates"}]
      end
    end)
  end

  def validate_fqdn(changeset, field, opts \\ []) do
    allow_port = Keyword.get(opts, :allow_port, false)

    validate_change(changeset, field, fn _current_field, value ->
      {fqdn, port} = split_port(value)
      fqdn_validation_errors = fqdn_validation_errors(field, fqdn)
      port_validation_errors = port_validation_errors(field, port, allow_port)
      fqdn_validation_errors ++ port_validation_errors
    end)
  end

  defp fqdn_validation_errors(field, fqdn) do
    if Regex.match?(~r/^([a-zA-Z0-9._-])+$/i, fqdn) do
      []
    else
      [{field, "#{fqdn} is not a valid FQDN"}]
    end
  end

  defp split_port(value) do
    case String.split(value, ":", parts: 2) do
      [prefix, port] ->
        case Integer.parse(port) do
          {port, ""} ->
            {prefix, port}

          _ ->
            {value, nil}
        end

      [value] ->
        {value, nil}
    end
  end

  defp port_validation_errors(_field, nil, _allow?),
    do: []

  defp port_validation_errors(field, _port, false),
    do: [{field, "setting port is not allowed"}]

  defp port_validation_errors(_field, port, _allow?) when 0 < port and port <= 65_535,
    do: []

  defp port_validation_errors(field, _port, _allow?),
    do: [{field, "port is not a number between 0 and 65535"}]

  def validate_ip_type_inclusion(changeset, field, types) do
    validate_change(changeset, field, fn _current_field, %{address: address} ->
      type = if tuple_size(address) == 4, do: :ipv4, else: :ipv6

      if type in types do
        []
      else
        [{field, "is not a supported IP type"}]
      end
    end)
  end

  def validate_in_cidr(changeset, ip_field, cidr) do
    validate_change(changeset, ip_field, fn _ip_field, ip ->
      if Domain.Types.CIDR.contains?(cidr, ip) do
        []
      else
        [{ip_field, "is not in the CIDR #{cidr}"}]
      end
    end)
  end

  def validate_not_in_cidr(changeset, ip_or_cidr_field, cidr, opts \\ []) do
    validate_change(changeset, ip_or_cidr_field, fn _ip_or_cidr_field, ip_or_cidr ->
      case Domain.Types.INET.cast(ip_or_cidr) do
        {:ok, ip_or_cidr} ->
          if Domain.Types.CIDR.contains?(cidr, ip_or_cidr) or
               Domain.Types.CIDR.contains?(ip_or_cidr, cidr) do
            message = Keyword.get(opts, :message, "can not be in the CIDR #{cidr}")
            [{ip_or_cidr_field, message}]
          else
            []
          end

        _other ->
          []
      end
    end)
  end

  def validate_and_normalize_cidr(changeset, field, _opts \\ []) do
    with {_data_or_changes, value} <- fetch_change(changeset, field),
         {:ok, cidr} <- Domain.Types.CIDR.cast(value) do
      {range_start, _range_end} = Domain.Types.CIDR.range(cidr)
      cidr = %{cidr | address: range_start}
      put_change(changeset, field, to_string(cidr))
    else
      :error ->
        changeset

      {:error, _reason} ->
        add_error(changeset, field, "is not a valid CIDR range")
    end
  end

  def validate_and_normalize_ip(changeset, field, _opts \\ []) do
    with {_data_or_changes, value} <- fetch_change(changeset, field),
         {:ok, ip} <- Domain.Types.IP.cast(value) do
      put_change(changeset, field, to_string(ip))
    else
      :error ->
        changeset

      {:error, _reason} ->
        add_error(changeset, field, "is not a valid IP address")
    end
  end

  def validate_base64(changeset, field) do
    validate_change(changeset, field, fn _cur, value ->
      case Base.decode64(value) do
        :error -> [{field, "must be a base64-encoded string"}]
        {:ok, _decoded} -> []
      end
    end)
  end

  def validate_omitted(changeset, fields) when is_list(fields) do
    Enum.reduce(fields, changeset, fn field, accumulated_changeset ->
      validate_omitted(accumulated_changeset, field)
    end)
  end

  def validate_omitted(changeset, field) when is_atom(field) do
    validate_change(changeset, field, fn
      _field, nil -> []
      _field, [] -> []
      field, _value -> [{field, "must not be present"}]
    end)
  end

  def validate_file(changeset, field, opts \\ []) do
    validate_change(changeset, field, fn _current_field, value ->
      extensions = Keyword.get(opts, :extensions, [])

      cond do
        not File.exists?(value) ->
          [{field, "file does not exist"}]

        extensions != [] and Path.extname(value) not in extensions ->
          [
            {field,
             "file extension is not supported, got #{Path.extname(value)}, " <>
               "expected one of #{inspect(extensions)}"}
          ]

        true ->
          []
      end
    end)
  end

  @doc """
  Takes value from `value_field` and puts it's hash of a given type to `hash_field`.
  """
  def put_hash(%Ecto.Changeset{} = changeset, value_field, type, opts) do
    hash_field = Keyword.fetch!(opts, :to)
    salt_field = Keyword.get(opts, :with_salt)
    nonce_field = Keyword.get(opts, :with_nonce)

    with {:ok, value} <- fetch_value(changeset, value_field),
         {:ok, nonce} <- fetch_hash_component(changeset, nonce_field),
         {:ok, salt} <- fetch_hash_component(changeset, salt_field) do
      put_change(changeset, hash_field, Domain.Crypto.hash(type, nonce <> value <> salt))
    else
      _ -> changeset
    end
  end

  defp fetch_value(changeset, value_field) do
    case fetch_change(changeset, value_field) do
      {:ok, ""} -> :error
      {:ok, value} when is_binary(value) -> {:ok, value}
      _other -> :error
    end
  end

  defp fetch_hash_component(_changeset, nil) do
    {:ok, ""}
  end

  defp fetch_hash_component(changeset, salt_field) do
    case fetch_change(changeset, salt_field) do
      {:ok, salt} when is_binary(salt) -> {:ok, salt}
      :error -> {:ok, ""}
    end
  end

  @doc """
  Validates that value in a given `value_field` equals to hash stored in `hash_field`.
  """
  def validate_hash(changeset, value_field, type, hash_field: hash_field) do
    with {:data, hash} <- fetch_field(changeset, hash_field) do
      validate_change(changeset, value_field, fn value_field, token ->
        if Domain.Crypto.equal?(type, token, hash) do
          []
        else
          [{value_field, {"is invalid", [validation: :hash]}}]
        end
      end)
    else
      {:changes, _hash} ->
        add_error(changeset, value_field, "can't be verified", validation: :hash)

      :error ->
        add_error(changeset, value_field, "is already verified", validation: :hash)
    end
  end

  def validate_if_true(%Ecto.Changeset{} = changeset, field, callback)
      when is_function(callback, 1) do
    case fetch_field(changeset, field) do
      {_data_or_changes, true} ->
        callback.(changeset)

      _else ->
        changeset
    end
  end

  def validate_if_changed(%Ecto.Changeset{} = changeset, field, callback)
      when is_function(callback, 1) do
    with {:ok, _value} <- fetch_change(changeset, field) do
      callback.(changeset)
    else
      _ -> changeset
    end
  end

  def validate_required_group(%Ecto.Changeset{} = changeset, fields) do
    if Enum.any?(fields, &(not empty?(changeset, &1))) do
      validate_required(changeset, fields)
    else
      changeset
    end
  end

  def validate_required_one_of(%Ecto.Changeset{} = changeset, fields) do
    if Enum.any?(fields, &(not empty?(changeset, &1))) do
      changeset
    else
      Enum.reduce(
        fields,
        changeset,
        &add_error(&2, &1, "one of these fields must be present: #{Enum.join(fields, ", ")}",
          validation: :one_of,
          one_of: fields
        )
      )
    end
  end

  def validate_datetime(changeset, field, greater_than: greater_than) do
    validate_change(changeset, field, fn _current_field, value ->
      if DateTime.compare(value, greater_than) == :gt do
        []
      else
        [{field, "must be greater than #{inspect(greater_than)}"}]
      end
    end)
  end

  def validate_date(changeset, field, greater_than: greater_than) do
    validate_change(changeset, field, fn _current_field, value ->
      if Date.compare(value, greater_than) == :gt do
        []
      else
        [{field, "must be greater than #{inspect(greater_than)}"}]
      end
    end)
  end

  @doc """
  Applies a validation function for every elements of the list.

  The validation function should take two arguments: field name and element value,
  and return the same structure as `validate_change/3`.
  """
  def validate_list_elements(%Ecto.Changeset{} = changeset, field, callback) do
    validate_change(changeset, field, fn _field, values ->
      values
      |> Enum.flat_map(&callback.(field, &1))
      |> Enum.uniq()
    end)
  end

  @doc """
  Removes change for a given field and original value from it from `changeset.params`.

  Even though `changeset.params` considered to be a private field it leaks values even
  after they are removed from a changeset if you `inspect(struct, structs: false)` or
  just access it directly.
  """
  def redact_field(%Ecto.Changeset{} = changeset, field) do
    changeset = delete_change(changeset, field)
    %{changeset | params: Map.drop(changeset.params, field_variations(field))}
  end

  defp field_variations(field) when is_atom(field), do: [field, Atom.to_string(field)]

  @doc """
  Puts the change if field is not changed or it's value is set to `nil`.
  """
  def put_default_value(changeset, _field, nil) do
    changeset
  end

  def put_default_value(changeset, field, from: source_field) do
    case fetch_field(changeset, source_field) do
      {_data_or_changes, value} -> put_default_value(changeset, field, value)
      :error -> changeset
    end
  end

  def put_default_value(changeset, field, value) do
    case fetch_field(changeset, field) do
      {:data, nil} -> put_change(changeset, field, maybe_apply(changeset, value))
      :error -> put_change(changeset, field, maybe_apply(changeset, value))
      _ -> changeset
    end
  end

  defp maybe_apply(_changeset, fun) when is_function(fun, 0), do: fun.()
  defp maybe_apply(changeset, fun) when is_function(fun, 1), do: fun.(changeset)
  defp maybe_apply(_changeset, value), do: value

  def trim_change(changeset, field) do
    update_change(changeset, field, fn
      nil -> nil
      changes when is_list(changes) -> Enum.map(changes, &String.trim/1)
      change -> String.trim(change)
    end)
  end

  def copy_change(changeset, from, to) do
    case fetch_change(changeset, from) do
      {:ok, nil} -> changeset
      {:ok, value} -> put_change(changeset, to, value)
      :error -> changeset
    end
  end

  @doc """
  Returns `true` when binary representation of Ecto UUID is valid, otherwise - `false`.
  """
  def valid_uuid?(binary) when is_binary(binary),
    do: match?(<<_::64, ?-, _::32, ?-, _::32, ?-, _::32, ?-, _::96>>, binary)

  def valid_uuid?(_binary),
    do: false
end
