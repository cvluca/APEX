#pragma once

#include "utils.h"
#include "string-fwd.h"

namespace apex {

// Wildcard characters
// Symbol |   Description
// ------------------------------------------------------------
// %      | Represents zero or more characters
// _      | Represents a single character
// []     | Represents any single character within the brackets *
// ^      | Represents any character not in the brackets *
// -      | Represents any single character within the specified range *
// {}     | Represents any escaped character **
// ------------------------------------------------------------
// * Not supported in PostgreSQL and MySQL databases.
// ** Supported only in Oracle databases.

enum TokenType {
  ANYSTAR,      // %
  ANY1,         // _
  LITERAL,      // Literal characters
  ENC_LITERAL,  // Literal characters with encryption
};

class StringTokenImpl
{
public:
  StringTokenImpl() = delete;

  // Constructor for encrypted literal with bit-slice segments and wildcard mask
  StringTokenImpl(std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> enc_segments,
                  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> wildcard_mask = nullptr)
      : type(ENC_LITERAL), enc_segments(std::move(enc_segments)), wildcard_mask(wildcard_mask) {}

  StringTokenImpl(char token)
      : token(token)
  {
    if (token == '%') {
      type = ANYSTAR;
    } else if (token == '_') {
      type = ANY1;
    } else if (token >= ' ' && token <= '~') {
      type = LITERAL;
    } else {
      OPENFHE_THROW("StringTokenImpl: unsupported character '" + std::string(1, token) + "'");
    }
  }

  TokenType GetType() const { return type; }

  // Get encrypted bit-slice segments for this character
  const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& GetEncSegments() const
  {
    if (type != ENC_LITERAL) {
      OPENFHE_THROW("StringTokenImpl::GetEncSegments: not an encrypted literal token");
    }
    return enc_segments;
  }

  // Get wildcard mask (1 if ANY1, 0 if normal character)
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> GetWildcardMask() const
  {
    if (type != ENC_LITERAL) {
      OPENFHE_THROW("StringTokenImpl::GetWildcardMask: not an encrypted literal token");
    }
    return wildcard_mask;
  }

  char Get() const
  {
    if (type == ENC_LITERAL) {
      OPENFHE_THROW("StringTokenImpl::GetToken: cannot get token from encrypted literal");
    }
    return token;
  }

private:
  TokenType type;
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> enc_segments;  // Bit-slice segments for encrypted literal
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> wildcard_mask;  // 1 if ANY1 wildcard, 0 if normal character
  char token;
};

// Create encrypted token with bit-slice segments and optional wildcard mask
inline StringToken MakeStringToken(
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> enc_segments,
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> wildcard_mask = nullptr)
{
  return std::make_shared<StringTokenImpl>(std::move(enc_segments), wildcard_mask);
}

inline StringToken MakeStringToken(char token)
{
  return std::make_shared<StringTokenImpl>(token);
}

} // namespace apex
