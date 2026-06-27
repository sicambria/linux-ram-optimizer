# linux-ram-optimizer — safe Linux RAM diagnostics and cache reclaim.
# Copyright (C) 2026 linux-ram-optimizer contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""linux-ram-optimizer: explain Linux memory use and reclaim cache safely.

The package is split into pure, side-effect-free parsing/analysis modules
(:mod:`ramopt.proc`, :mod:`ramopt.analyze`) and thin I/O modules
(:mod:`ramopt.collect`, :mod:`ramopt.remediate`).  This separation keeps the
logic fully unit-testable on captured ``/proc`` fixtures without root.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
