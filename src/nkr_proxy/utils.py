# Copyright 2019 Ministry of Education and Culture, Finland
# SPDX-License-Identifier: MIT

import sys


def executing_tests():
    """
    When automated tests are being executed, the module 'pytest' is loaded.
    """
    return 'pytest' in sys.modules
