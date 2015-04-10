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
from re import sub
import urllib
import sys
import uuid

from django.utils.translation import ugettext_lazy as _
from geonode import GeoNodeException
from geonode.geoserver.helpers import ogc_server_settings

from owslib.sos import SensorObservationService
from owslib.util import nspath_eval
from owslib.swe.observation.sos100 import namespaces


logger = logging.getLogger(__name__)


def sos_cf_observation(response):
    """Return data from a SOS GetObservation XML as a CF_SimpleObservation
    record (JSON).

    Example
    =======
    {
        "type":"CF_SimpleObservation",
        "parameter":{"id":"ed221bf0-d075-012d-287e-34159e211071"},
        "phenomenonTime":"2010-11-12T13:45:00Z",
        "procedure":{"id":"WS:123:123", "type":"Sensor"},
        "featureOfInterest":{
		        "type":"Feature",
		        "geometry":null,
		        "properties":{"id":"43:CSIR:PRETORIA"}
	        },
        "observedProperty":{"type":"TimeSeries"},
        "result":{
	        "dimensions":{
		        "time":3
	        },
	        "variables":{
		        "time":{"dimensions":["time"], "units":"isoTime"},
		        "power_load":{"dimensions":["time"], "units":"MW"}
	        },
	        "data":{
		        "time":["2010-11-12T13:45:00Z","2010-11-12T13:50:00Z","2010-11-12T13:55:00Z"],
		        "power_load":[23.0,23.1,23.0]
	        }
        }
    }
    """
    def remove_attr_namespace(elem):
        """Remove attribute namespace from element."""
        to_delete=[]
        to_set={}
        for attr_name in elem.attrib:
            if attr_name[0]=='{':
                old_val = elem.attrib[attr_name]
                to_delete.append(attr_name)
                attr_name = attr_name[attr_name.index('}',1)+1:]
                to_set[attr_name] = old_val
        for key in to_delete:
            elem.attrib.pop(key)
        elem.attrib.update(to_set)
        return elem

    def get_uom(elem):
        _uom = elem.find(nspath_eval('swe:uom', namespaces))
        if _uom is not None:
            _uom = remove_attr_namespace(_uom)
            return _uom.attrib['href']
        else:
            return ''

    # check response
    results = []
    try:
        _tree = etree.fromstring(response)
    except ValueError:
        return results
    # process XML response to extract data
    foi_id, proc_id, obs_id, length = None, None, None, 0
    variables, data = {}, {}
    # observation
    obs = _tree.findall(nspath_eval('om:member/om:Observation', namespaces))
    if obs and len(obs) > 0:
        _obs = remove_attr_namespace(obs[0])
        obs_id = _obs.attrib['id']
    # feature-of-interest
    foi = _tree.findall(nspath_eval('om:member/om:Observation/om:featureOfInterest', namespaces))
    if foi and len(foi) > 0:
        _foi = remove_attr(foi[0])
        foi_id = _foi.attrib['title']
    # procedure/sensor
    proc = _tree.findall(nspath_eval('om:member/om:Observation/om:procedure', namespaces))
    if proc and len(proc) > 0:
        _proc = remove_attr_namespace(proc[0])
        proc_id = _proc.attrib['href']
    # observed data
    data = _tree.findall(
        nspath_eval('om:member/om:Observation/om:result/swe:DataArray',
        namespaces))
    for datum in data:
        # size of data
        _length = datum.find(nspath_eval('swe:elementCount/swe:Count/swe:value', namespaces))
        if _length is not None:
            length = _length.txt
        # fields (variables)
        fieldnames = []
        fields = datum.findall(
            nspath_eval('swe:elementType/swe:DataRecord/swe:field', namespaces))
        for field in fields:
            fieldname = field.attrib['name']
            _time = field.find(nspath_eval('swe:Time', namespaces))
            if _time is not None:
                # TODO validate that time is in ISO time format (ISO 8601)
                variables["time"] = {"dimensions": ["time"], "units": "isoTime"}
                data["time"] = []
                fieldnames.append("time")
            else:
                _var = field.find(nspath_eval('swe:Text', namespaces))
                variables[fieldname] = {"dimensions": ["time"], "units": get_uom(_var)}
                data[fieldname] = []
                fieldnames.append(fieldname)
        # data for each variable
        encoding = datum.find(
            nspath_eval('swe:encoding/swe:TextBlock', namespaces))
        separators = (encoding.attrib['decimalSeparator'],
                      encoding.attrib['tokenSeparator'],
                      encoding.attrib['blockSeparator'])
        values = datum.find(nspath_eval('swe:values', namespaces))
        lines = values.text.split(separators[2]) # list of lines
        for line in lines:
            items = line.split(separators[1])  # list of items in single line
            for key, item in enumerate(items):
                if item:
                    data[fieldnames[key]].append(item)
    # save results in dictionary
    result = {}
    result['type'] = "CF_SimpleObservation"
    result['parameter'] = {"id": obs_id}  #str( uuid.uuid4())
    result['procedure'] =  {
        "id": proc_id,
        "type": "Sensor"
    }
    result['phenomenonTime'] = data["time"][-1]  # last datetime value
    result['featureOfInterest'] = {
        "type": "Feature",
        # TODO check if geometry is required
        "geometry": None,
        "properties": {"id": foi_id}
    }
    result['observedProperty'] = {"type": "TimeSeries"}
    result['result'] = {
        "dimensions": {"time": length}, # length of data array  #len(data["time"])
        "variables": variables,
        "data": data
    }
    results.append(result)

    return results


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
    print >>sys.stderr, "XML:\n", response
    try:
        _tree = etree.fromstring(response)
    except ValueError:
        return result
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
        are separated by "/"; e.g. 2015-01-02T08:00:00+02/2015-01-02T11:00:00+02
    feature : string
        filters results for the ID of a procedure/feature_of_interest
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
            procedure=feature)
    else:
        return _sos.get_observation(
            offerings=sos_offerings, responseFormat=responseFormat,
            observedProperties=observedProperties, eventTime=eventTime)

