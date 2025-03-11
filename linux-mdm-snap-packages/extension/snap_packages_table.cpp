#include <boost/algorithm/string.hpp>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/process/process.h>
#include <osquery/utils/conversions/split.h>

#include "snap_packages_table.h"

namespace osquery {
namespace tables {

TableColumns SnapPackagesTablePlugin::columns() const {
  return {
      std::make_tuple("name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("version", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("rev", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("tracking", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("publisher", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("notes", TEXT_TYPE, ColumnOptions::DEFAULT),
  };
}

QueryData SnapPackagesTablePlugin::generate(QueryContext& context) {
  QueryData results;

  // Execute the snap list command
  auto cmd = "/usr/bin/snap list";
  std::vector<std::string> args;
  auto output = osquery::split(cmd, " ");
  if (output.size() > 1) {
    cmd = output.at(0);
    for (size_t i = 1; i < output.size(); i++) {
      args.push_back(output.at(i));
    }
  }

  // Get output from the command
  std::vector<std::string> lines;
  auto status = osquery::procExecute(cmd, args, lines);
  if (!status.ok()) {
    LOG(ERROR) << "Error running snap list: " << status.getMessage();
    return results;
  }

  // Skip header (first two lines contain header info)
  if (lines.size() < 2) {
    return results;
  }

  // Process each line of output
  for (size_t i = 2; i < lines.size(); i++) {
    auto line = lines[i];
    if (line.empty()) {
      continue;
    }

    // Split the line by whitespace to get columns
    std::vector<std::string> columns;
    boost::trim(line);
    boost::split(columns, line, boost::is_any_of(" \t"), boost::token_compress_on);

    // Ensure we have the minimum required columns
    if (columns.size() < 5) {
      continue;
    }

    Row r;
    r["name"] = columns[0];
    r["version"] = columns[1];
    r["rev"] = columns[2];
    r["tracking"] = columns[3];
    r["publisher"] = columns[4];
    
    // Notes column may not always be present
    if (columns.size() > 5) {
      r["notes"] = columns[5];
    } else {
      r["notes"] = "";
    }

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery