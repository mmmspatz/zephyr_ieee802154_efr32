# Copyright (c) 2026 LeafLabs, LLC
#
# SPDX-License-Identifier: Apache-2.0

zephyr_library_sources_ifdef(CONFIG_IEEE802154_EFR32 ieee802154_efr32.c)
zephyr_library_sources_ifdef(CONFIG_IEEE802154_EFR32_DEBUG ieee802154_efr32_debug.c)
