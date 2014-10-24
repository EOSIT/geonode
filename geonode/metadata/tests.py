#########################################################################
#
# Copyright (C) 2012 OpenPlans
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from django.test import TestCase
from geonode.metadata import wms_layer_metadata, wfs_layer_metadata


class MetaDataTest(TestCase):

    def test_wms_layer_metadata(self):
        """
        Tests the wms_layer_metadata function works.
        """
        wms = wms_layer_metadata()  # TODO

    def test_wfs_layer_metadata(self):
        """
        Tests the wfs_layer_metadata function works.
        """
        wfs = wfs_layer_metadata()  # TODO
