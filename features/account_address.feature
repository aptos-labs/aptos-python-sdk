Feature: Account Address
"""
AccountAddress is a 32-byte value that represents an address on chain.
"""

  Scenario Outline: Parse account address <label>
    Given string <str>
    When I parse the account address
    Then the result should be address <address>
    Examples:
      | label                     | str                                          | address                                    |
      | address one short         | "0x1"                                        | 0x1                                        |
      | address one long          | "0x0000000000000000000000000000000000000001" | 0x1                                        |
      | address two short         | "0x2"                                        | 0x2                                        |
      | address two long          | "0x0000000000000000000000000000000000000002" | 0x2                                        |
      | full address              | "0x1111111111111111111111111111111111111112" | 0x1111111111111111111111111111111111111112 |
      | address with leading 0    | "0x0111111111111111111111111111111111111112" | 0x0111111111111111111111111111111111111112 |
      | address missing leading 0 | "0x111111111111111111111111111111111111112"  | 0x111111111111111111111111111111111111112  |

  Scenario Outline: Address <label> to string
  """
  TODO: AIP-40 doesn't shorten 0xB
  TODO: Uppercase or lowercase?
  """
    Given address <address>
    When I convert the address to a string
    Then the result should be string <str>

    Examples:
      | label                  | str                                                                  | address                                                            |
      | address one            | "0x1"                                                                | 0x1                                                                |
      | address two            | "0x2"                                                                | 0x2                                                                |
      | address two long       | "0x2"                                                                | 0x0000000000000000000000000000000000000002                         |
      | address A              | "0xa"                                                                | 0xA                                                                |
      | address B              | "0xb"                                                                | 0xB                                                                |
      | full address           | "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef |
      | address with leading 0 | "0x0000000000000000000000000111111111111111111111111111111111111112" | 0x0111111111111111111111111111111111111112                         |

  Scenario Outline: Address <label> to string long
  """
  This is required for indexer support
  """
    Given address <address>
    When I convert the address to a string long
    Then the result should be string <str>

    Examples:
      | label                     | str                                                                  | address                                                            |
      | address one               | "0x0000000000000000000000000000000000000000000000000000000000000001" | 0x1                                                                |
      | address two               | "0x0000000000000000000000000000000000000000000000000000000000000002" | 0x2                                                                |
      | address A                 | "0x000000000000000000000000000000000000000000000000000000000000000a" | 0xA                                                                |
      | address B                 | "0x000000000000000000000000000000000000000000000000000000000000000b" | 0xB                                                                |
      | full address              | "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef |
      | address with leading 0    | "0x0000000000000000000000000111111111111111111111111111111111111112" | 0x0111111111111111111111111111111111111112                         |
      | address missing leading 0 | "0x0000000000000000000000000111111111111111111111111111111111111112" | 0x111111111111111111111111111111111111112                          |


  Scenario Outline: Parse account address with invalid address <label>
    Given string "<address>"
    When I parse the account address
    Then I should fail to parse the account address
    Examples:
      | label                       | address                                                             |
      | address no digits           | 0x                                                                  |
      | address too long            | 0xA0000000000000000000000000000000000000000000000000000000000000001 |
      | address too long with zeros | 0x00000000000000000000000000000000000000000000000000000000000000001 |
      | address invalid character   | 0xG                                                                 |

