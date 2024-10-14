#include <osquery/sdk/sdk.h>
#include <osquery/sdk/tables.h>

namespace osquery {
namespace tables {

QueryData genSnapPackages(QueryContext& context) {
  QueryData results;

  // Execute the snap list --all command
  auto snap_list = SQL::selectAllFrom("shell", "command='snap list --all'");

  // Loop through the output lines of the command
  for (const auto& row : snap_list) {
    Row r;

    // Parse and map the snap list output fields (assuming columns are name, version, rev, tracking, publisher, notes)
    r["name"] = row.at("name");
    r["version"] = row.at("version");
    r["rev"] = row.at("rev");
    r["tracking"] = row.at("tracking");
    r["publisher"] = row.at("publisher");
    r["notes"] = row.at("notes");

    results.push_back(r);
  }

  return results;
}

TableColumns columns() {
  return {
      std::make_tuple("name", TEXT_TYPE, "Snap package name"),
      std::make_tuple("version", TEXT_TYPE, "Snap package version"),
      std::make_tuple("rev", TEXT_TYPE, "Revision number"),
      std::make_tuple("tracking", TEXT_TYPE, "Tracking channel"),
      std::make_tuple("publisher", TEXT_TYPE, "Publisher of the package"),
      std::make_tuple("notes", TEXT_TYPE, "Any notes for the package"),
  };
}

} // namespace tables
} // namespace osquery

REGISTER_EXTERNAL(tables::genSnapPackages, tables::columns);

