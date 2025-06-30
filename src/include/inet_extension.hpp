//===----------------------------------------------------------------------===//
//                         DuckDB
//
// inet_extension.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"

namespace duckdb {

class InetExtension : public Extension {
public:
  void Load(ExtensionLoader &loader) override;
  std::string Name() override;
  std::string Version() const override;

  static ScalarFunctionSet GetEscapeFunctionSet();
  static ScalarFunction GetUnescapeFunction();
};

} // namespace duckdb
