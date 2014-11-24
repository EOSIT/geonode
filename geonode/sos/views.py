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

import os
import datetime
import json
import urllib2

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from geonode.layers.views import _resolve_layer, _PERMISSION_MSG_VIEW

from ows_sos import sos_swe_data_list, sos_observation_xml


def ajax_login_required(f):
    """Validate that user is authenticated; otherwise return a JSON error."""
    def wrap(request, *args, **kwargs):
        if not request.user.is_authenticated():
            out = {'error': 'Not logged in.'}
            return HttpResponse(
                json.dumps(out),
                mimetype='application/json',
                status=400)
        return f(request, *args, **kwargs)
    wrap.__doc__=f.__doc__
    wrap.__name__=f.__name__
    return wrap


@ajax_login_required
def sos_layer_metadata(request, layername):
    """Return SOS metadata for a layer specified by name.
    """
    # TODO
    return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=404) 


@ajax_login_required
def sos_layer_data(request, layername):
    """Return SOS data for a layer specified by name.

    Access to the layer keywords is needed to determine the additional 
    characteristics of a layer.
 
    Access to the layer's supplemental information at this level must be 
    parsed for appropriate function.
    """
    out = {}
    layer = _resolve_layer(request, 
                           layername, 
                           'layers.view_layer', 
                           _PERMISSION_MSG_VIEW)
    if 'feature' in request.GET:
        feature = request.GET['feature']
    else:
        feature = None
    keys = [lkw.name for lkw in layer.keywords.all()]
    sup_inf_str = str(layer.supplemental_information) 
    if "sos" in keys or "SOS" in keys:
        return extract_sos_data(feature, sup_inf_str, format='json', time=None)
    else:
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=400)


def extract_sos_data(feature, supplementary_info, data_format='json', time=None):
    """Return SOS data in data format for a layer specifying a valid SOS URL.
    
    Parameters
    ----------
    feature : string
        the ID of a feature from the WFS; this is used as a link to a
        corresponding "feature_of_interest" in the SOS
    supplementary_info : dictionary
        a set of parameters used to access a SOS.  For example:
            {"sos_url": "http://sos.server.com:8080/sos", 
             "observedProperties": ["urn:ogc:def:phenomenon:OGC:1.0.30:temperature"], 
             "offerings": ["WEATHER"]}
    data_format: string
        a value in the set [csv|json]; defaults to json
    time : string
        Optional.   Time should conform to ISO format: YYYY-MM-DDTHH:mm:ss+-HH
        Instance is given as one time value. Periods of time (start and end) are
        separated by "/". Example: 2009-06-26T10:00:00+01/2009-06-26T11:00:00+01
    """
    import csv
    sup_info = eval(supplementary_info)
    offerings = sup_info.get('offerings')
    url = sup_info.get('sos_url')
    observedProperties = sup_info.get('observedProperties')
    time = time
    XML = sos_observation_xml(
        url, offerings=offerings, observedProperties=observedProperties, 
        allProperties=False, feature=feature, eventTime=time)
    lists = sos_swe_data_list(XML)
    if data_format ==  'csv':
        sos_data = HttpResponse(mimetype='text/csv')
        sos_data['Content-Disposition'] = 'attachment;filename=sos.csv'
        writer = csv.writer(sos_data)
        # headers are included by default in lists, can set show_headers to false
        #   in the sos_swe_data_list() in ows.py
        writer.writerows(lists)
        return sos_data
    else:  # json is default
        service_result = {'format': {},
                          'data': lists,
                          'style': {}}
        return HttpResponse(
            json.dumps(service_result), 
            mimetype="application/json",
            status=200)
