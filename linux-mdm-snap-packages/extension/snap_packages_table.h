#pragma once

#include <osquery/core/tables.h>
#include <osquery/sdk/sdk.h>

namespace osquery {
namespace tables {

/**
 * @brief Table plugin for snap packages
 */
class SnapPackagesTablePlugin : public TablePlugin {
 public:
  /**
   * @brief Return the table's column definitions
   */
  TableColumns columns() const override;

  /**
   * @brief Generate the table data
   */
  QueryData generate(QueryContext& context) override;
};

} // namespace tables
} // namespace osquery