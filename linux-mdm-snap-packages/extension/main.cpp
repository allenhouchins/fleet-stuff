#include <osquery/core/system.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sdk/sdk.h>

#include "snap_packages_table.h"

using namespace osquery;

// Extension information
EXTENSION_MAIN("snap_packages", "1.0.0", "Extension for querying snap packages");

namespace osquery {

/**
 * @brief Initialize the extension by registering plugins
 *
 * @param name The extension's name
 */
void initializeSnapPackagesExtension(const std::string& name) {
  // Register our table plugin
  REGISTER(tables::SnapPackagesTablePlugin, "table", "snap_packages");

  // Log the registered tables
  LOG(INFO) << "Extension " << name << " registered " << Registry::get().count() << " plugins";
}

} // namespace osquery

int main(int argc, char* argv[]) {
  // Initialize the extension with the program name and argv
  auto status = osquery::initializeExtension(argc, argv, "snap_packages");
  
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return EXIT_FAILURE;
  }

  // Initialize our table plugins
  osquery::initializeSnapPackagesExtension("snap_packages");

  // Start the extension
  status = osquery::startExtension("snap_packages", "1.0.0");
  
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    return EXIT_FAILURE;
  }

  // Wait for extension to exit
  osquery::Initializer::shutdownNow();
  return EXIT_SUCCESS;
}