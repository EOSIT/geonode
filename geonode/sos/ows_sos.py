# -*- coding: utf-8 -*-
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

import logging
from lxml import etree
import urllib
import sys

from django.utils.translation import ugettext_lazy as _
from geonode import GeoNodeException
from geonode.geoserver.helpers import ogc_server_settings

from owslib.sos import SensorObservationService
from owslib.util import nspath_eval
from owslib.swe.observation.sos100 import namespaces

from re import sub

logger = logging.getLogger(__name__)


def sos_swe_data_list(response, constants=[], show_headers=True):
    """Return data values from SOS XML <swe:value> tag as a list of lists.
    
    Parameters
    ----------
    constants : list
        Fixed values appended to each nested list
    show_headers : boolean
        if True, inserts list of headers as first nested list
    """
    result = []
    headers = []
    #print >>sys.stderr, "XML:\n", response
    _tree = etree.fromstring(response)
    data = _tree.findall(
        nspath_eval('om:member/om:Observation/om:result/swe:DataArray', 
        namespaces))
    for datum in data:
        encoding = datum.find(
            nspath_eval('swe:encoding/swe:TextBlock', namespaces))
        separators = (encoding.attrib['decimalSeparator'], 
                      encoding.attrib['tokenSeparator'], 
                      encoding.attrib['blockSeparator']) 

        if show_headers and not headers:  # only for first dataset
            fields = datum.findall(
                nspath_eval('swe:elementType/swe:DataRecord/swe:field', namespaces))
            for field in fields:
                headers.append(field.attrib['name'])
            if headers:
                result.append(headers)

        values = datum.find(nspath_eval('swe:values', namespaces))
        lines = values.text.split(separators[2]) # list of lines
        for line in lines:
            items = line.split(separators[1])  # list of items in single line
            if items:
                if constants:
                    items += constants
                result.append(items)
    return result


def sos_observation_xml(url, version='1.0.0', xml=None, offerings=[], 
                        responseFormat=None, observedProperties=[], 
                        eventTime=None, feature=None, allProperties=False):
    """Return the XML from a SOS GetObservation request.

    Parameters
    ----------
    url : string
        Full HTTP address of SOS
    version: string
        Version number of the SOS (e.g. 1.0.0)
    offerings : list
        selected offerings from SOS; defaults to all available
    responseFormat : string
        desire format for result data 
    observedProperties : list
        filters results for selected properties from SOS; defaults to first one
        (unless allProperties is True)
    eventTime : string
        filters results for a specified instant or period.
        Use ISO format YYYY-MM-DDTHH:mm:ss+-HH  Periods of time (start and end) 
        are separated by "/"; e.g. 2009-06-26T10:00:00+01/2009-06-26T11:00:00+01
    feature : string
        filters results for the ID of a feature_of_interest
    allProperties : boolean
        if allProperties is True, filters results for all properties (and
        ignores any items in the observedProperties)
    """
    # GetCapabilites of SOS
    _sos = SensorObservationService(url, version=version or '1.0.0', xml=xml or None) 
    # process any supplied offerings
    if offerings:
        for off in _sos.offerings:  # look for matching IDs
            _offerings = [off for off in _sos.offerings if off.id in offerings]
    else:
        _offerings = []
    # get offering IDs to be used
    offerings_objs = _offerings or  _sos.offerings
    sos_offerings = [off.id for off in offerings_objs]
    responseFormat = responseFormat or offerings_objs[0].response_formats[0]
    if not allProperties:
        observedProperties = observedProperties or [offering.observed_properties[0]]
    else:
        observedProperties = offering.observed_properties
    eventTime = eventTime

    if feature:
        return _sos.get_observation(
            offerings=sos_offerings, responseFormat=responseFormat,
            observedProperties=observedProperties, eventTime=eventTime,
            FEATUREOFINTEREST=feature)
    else:
        return _sos.get_observation(
            offerings=sos_offerings, responseFormat=responseFormat,
            observedProperties=observedProperties, eventTime=eventTime)
