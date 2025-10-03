//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <nfcsigner/nfcsigner_plugin.h>

void fl_register_plugins(FlPluginRegistry* registry) {
  g_autoptr(FlPluginRegistrar) nfcsigner_registrar =
      fl_plugin_registry_get_registrar_for_plugin(registry, "NfcsignerPlugin");
  nfcsigner_plugin_register_with_registrar(nfcsigner_registrar);
}
