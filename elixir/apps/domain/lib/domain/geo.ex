defmodule Domain.Geo do
  @radius_of_earth_km 6371.0

  # Since most of our customers are from US we use
  # geographic center of USA as default coordinates
  @default_coordinates {39.8283, -98.5795}

  @coordinates_by_code %{
                         "AF" => {33, 65},
                         "AX" => {60.116667, 19.9},
                         "AL" => {41, 20},
                         "DZ" => {28, 3},
                         "AS" => {-14.33333333, -170},
                         "AD" => {42.5, 1.5},
                         "AO" => {-12.5, 18.5},
                         "AI" => {18.25, -63.16666666},
                         "AQ" => {-74.65, 4.48},
                         "AG" => {17.05, -61.8},
                         "AR" => {-34, -64},
                         "AM" => {40, 45},
                         "AW" => {12.5, -69.96666666},
                         "AU" => {-27, 133},
                         "AT" => {47.33333333, 13.33333333},
                         "AZ" => {40.5, 47.5},
                         "BS" => {24.25, -76},
                         "BH" => {26, 50.55},
                         "BD" => {24, 90},
                         "BB" => {13.16666666, -59.53333333},
                         "BY" => {53, 28},
                         "BE" => {50.83333333, 4},
                         "BZ" => {17.25, -88.75},
                         "BJ" => {9.5, 2.25},
                         "BM" => {32.33333333, -64.75},
                         "BT" => {27.5, 90.5},
                         "BO" => {-17, -65},
                         "BQ" => {12.15, -68.266667},
                         "BA" => {44, 18},
                         "BW" => {-22, 24},
                         "BV" => {-54.43333333, 3.4},
                         "BR" => {-10, -55},
                         "IO" => {-6, 71.5},
                         "VG" => {18.431383, -64.62305},
                         "VI" => {18.34, -64.93},
                         "BN" => {4.5, 114.66666666},
                         "BG" => {43, 25},
                         "BF" => {13, -2},
                         "BI" => {-3.5, 30},
                         "KH" => {13, 105},
                         "CM" => {6, 12},
                         "CA" => {60, -95},
                         "CV" => {16, -24},
                         "KY" => {19.5, -80.5},
                         "CF" => {7, 21},
                         "TD" => {15, 19},
                         "CL" => {-30, -71},
                         "CN" => {35, 105},
                         "CX" => {-10.5, 105.66666666},
                         "CC" => {-12.5, 96.83333333},
                         "CO" => {4, -72},
                         "KM" => {-12.16666666, 44.25},
                         "CG" => {-1, 15},
                         "CD" => {0, 25},
                         "CK" => {-21.23333333, -159.76666666},
                         "CR" => {10, -84},
                         "HR" => {45.16666666, 15.5},
                         "CU" => {21.5, -80},
                         "CW" => {12.116667, -68.933333},
                         "CY" => {35, 33},
                         "CZ" => {49.75, 15.5},
                         "DK" => {56, 10},
                         "DJ" => {11.5, 43},
                         "DM" => {15.41666666, -61.33333333},
                         "DO" => {19, -70.66666666},
                         "EC" => {-2, -77.5},
                         "EG" => {27, 30},
                         "SV" => {13.83333333, -88.91666666},
                         "GQ" => {2, 10},
                         "ER" => {15, 39},
                         "EE" => {59, 26},
                         "ET" => {8, 38},
                         "FK" => {-51.75, -59},
                         "FO" => {62, -7},
                         "FJ" => {-18, 175},
                         "FI" => {64, 26},
                         "FR" => {46, 2},
                         "GF" => {4, -53},
                         "PF" => {-15, -140},
                         "TF" => {-49.25, 69.167},
                         "GA" => {-1, 11.75},
                         "GM" => {13.46666666, -16.56666666},
                         "GE" => {42, 43.5},
                         "DE" => {51, 9},
                         "GH" => {8, -2},
                         "GI" => {36.13333333, -5.35},
                         "GR" => {39, 22},
                         "GL" => {72, -40},
                         "GD" => {12.11666666, -61.66666666},
                         "GP" => {16.25, -61.583333},
                         "GU" => {13.46666666, 144.78333333},
                         "GT" => {15.5, -90.25},
                         "GG" => {49.46666666, -2.58333333},
                         "GN" => {11, -10},
                         "GW" => {12, -15},
                         "GY" => {5, -59},
                         "HT" => {19, -72.41666666},
                         "HM" => {-53.1, 72.51666666},
                         "VA" => {41.9, 12.45},
                         "HN" => {15, -86.5},
                         "HU" => {47, 20},
                         "HK" => {22.25, 114.16666666},
                         "IS" => {65, -18},
                         "IN" => {20, 77},
                         "ID" => {-5, 120},
                         "CI" => {8, -5},
                         "IR" => {32, 53},
                         "IQ" => {33, 44},
                         "IE" => {53, -8},
                         "IM" => {54.25, -4.5},
                         "IL" => {31.5, 34.75},
                         "IT" => {42.83333333, 12.83333333},
                         "JM" => {18.25, -77.5},
                         "JP" => {36, 138},
                         "JE" => {49.25, -2.16666666},
                         "JO" => {31, 36},
                         "KZ" => {48, 68},
                         "KE" => {1, 38},
                         "KI" => {1.41666666, 173},
                         "KW" => {29.5, 45.75},
                         "KG" => {41, 75},
                         "LA" => {18, 105},
                         "LV" => {57, 25},
                         "LB" => {33.83333333, 35.83333333},
                         "LS" => {-29.5, 28.5},
                         "LR" => {6.5, -9.5},
                         "LY" => {25, 17},
                         "LI" => {47.26666666, 9.53333333},
                         "LT" => {56, 24},
                         "LU" => {49.75, 6.16666666},
                         "MO" => {22.16666666, 113.55},
                         "MK" => {41.83333333, 22},
                         "MG" => {-20, 47},
                         "MW" => {-13.5, 34},
                         "MY" => {2.5, 112.5},
                         "MV" => {3.25, 73},
                         "ML" => {17, -4},
                         "MT" => {35.83333333, 14.58333333},
                         "MH" => {9, 168},
                         "MQ" => {14.666667, -61},
                         "MR" => {20, -12},
                         "MU" => {-20.28333333, 57.55},
                         "YT" => {-12.83333333, 45.16666666},
                         "MX" => {23, -102},
                         "FM" => {6.91666666, 158.25},
                         "MD" => {47, 29},
                         "MC" => {43.73333333, 7.4},
                         "MN" => {46, 105},
                         "ME" => {42.5, 19.3},
                         "MS" => {16.75, -62.2},
                         "MA" => {32, -5},
                         "MZ" => {-18.25, 35},
                         "MM" => {22, 98},
                         "NA" => {-22, 17},
                         "NR" => {-0.53333333, 166.91666666},
                         "NP" => {28, 84},
                         "NL" => {52.5, 5.75},
                         "NC" => {-21.5, 165.5},
                         "NZ" => {-41, 174},
                         "NI" => {13, -85},
                         "NE" => {16, 8},
                         "NG" => {10, 8},
                         "NU" => {-19.03333333, -169.86666666},
                         "NF" => {-29.03333333, 167.95},
                         "KP" => {40, 127},
                         "MP" => {15.2, 145.75},
                         "NO" => {62, 10},
                         "OM" => {21, 57},
                         "PK" => {30, 70},
                         "PW" => {7.5, 134.5},
                         "PS" => {31.9, 35.2},
                         "PA" => {9, -80},
                         "PG" => {-6, 147},
                         "PY" => {-23, -58},
                         "PE" => {-10, -76},
                         "PH" => {13, 122},
                         "PN" => {-25.06666666, -130.1},
                         "PL" => {52, 20},
                         "PT" => {39.5, -8},
                         "PR" => {18.25, -66.5},
                         "QA" => {25.5, 51.25},
                         "XK" => {42.666667, 21.166667},
                         "RE" => {-21.15, 55.5},
                         "RO" => {46, 25},
                         "RU" => {60, 100},
                         "RW" => {-2, 30},
                         "BL" => {18.5, -63.41666666},
                         "SH" => {-15.95, -5.7},
                         "KN" => {17.33333333, -62.75},
                         "LC" => {13.88333333, -60.96666666},
                         "MF" => {18.08333333, -63.95},
                         "PM" => {46.83333333, -56.33333333},
                         "VC" => {13.25, -61.2},
                         "WS" => {-13.58333333, -172.33333333},
                         "SM" => {43.76666666, 12.41666666},
                         "ST" => {1, 7},
                         "SA" => {25, 45},
                         "SN" => {14, -14},
                         "RS" => {44, 21},
                         "SC" => {-4.58333333, 55.66666666},
                         "SL" => {8.5, -11.5},
                         "SG" => {1.36666666, 103.8},
                         "SX" => {18.033333, -63.05},
                         "SK" => {48.66666666, 19.5},
                         "SI" => {46.11666666, 14.81666666},
                         "SB" => {-8, 159},
                         "SO" => {10, 49},
                         "ZA" => {-29, 24},
                         "GS" => {-54.5, -37},
                         "KR" => {37, 127.5},
                         "ES" => {40, -4},
                         "LK" => {7, 81},
                         "SD" => {15, 30},
                         "SS" => {7, 30},
                         "SR" => {4, -56},
                         "SJ" => {78, 20},
                         "SZ" => {-26.5, 31.5},
                         "SE" => {62, 15},
                         "CH" => {47, 8},
                         "SY" => {35, 38},
                         "TW" => {23.5, 121},
                         "TJ" => {39, 71},
                         "TZ" => {-6, 35},
                         "TH" => {15, 100},
                         "TL" => {-8.83333333, 125.91666666},
                         "TG" => {8, 1.16666666},
                         "TK" => {-9, -172},
                         "TO" => {-20, -175},
                         "TT" => {11, -61},
                         "TN" => {34, 9},
                         "TR" => {39, 35},
                         "TM" => {40, 60},
                         "TC" => {21.75, -71.58333333},
                         "TV" => {-8, 178},
                         "UG" => {1, 32},
                         "UA" => {49, 32},
                         "AE" => {24, 54},
                         "GB" => {54, -2},
                         "US" => {38, -97},
                         "UY" => {-33, -56},
                         "UZ" => {41, 64},
                         "VU" => {-16, 167},
                         "VE" => {8, -66},
                         "VN" => {16.16666666, 107.83333333},
                         "WF" => {-13.3, -176.2},
                         "EH" => {24.5, -13},
                         "YE" => {15, 48},
                         "ZM" => {-15, 30},
                         "ZW" => {-20, 30}
                       }
                       |> Enum.map(fn {code, {lat, lon}} -> {code, {lat * 1.0, lon * 1.0}} end)
                       |> Map.new()

  def fetch_radius_of_earth_km! do
    @radius_of_earth_km
  end

  def distance({lat1, lon1}, {lat2, lon2}) do
    d_lat = degrees_to_radians(lat2 - lat1)
    d_lon = degrees_to_radians(lon2 - lon1)

    a =
      :math.sin(d_lat / 2) * :math.sin(d_lat / 2) +
        :math.cos(degrees_to_radians(lat1)) * :math.cos(degrees_to_radians(lat2)) *
          :math.sin(d_lon / 2) * :math.sin(d_lon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))

    @radius_of_earth_km * c
  end

  defp degrees_to_radians(deg) do
    deg * :math.pi() / 180
  end

  def maybe_put_default_coordinates(country_code, {nil, nil}) do
    Map.get(@coordinates_by_code, country_code, @default_coordinates)
  end

  def maybe_put_default_coordinates(_country_code, {lat, lon}) do
    {lat, lon}
  end
end
