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
import urllib2

from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import HttpResponse

from owslib.wms import WebMapService
from owslib.wfs import WebFeatureService


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
def wms_layer_metadata(request, data_format='json', keyword=None):
    """Return formatted metadata for a WMS layer(s) for a previously 
    authenticated user.
    
    A keyword is used to filter for the required layer(s)
    
    Results:
        {"base_url": "http://server.co.za:1080/geoserver/wms/", 
         "date_indices": [
            "2014-09-21T00:00:00.000Z", "2014-10-15T00:00:00.000Z", 
            "2014-11-08T00:00:00.000Z", "2014-12-02T00:00:00.000Z"], 
         "layer_name": "test_displacement_wgs84"}
    """
    if keyword:
        WMS_KEYWORD = keyword
    else:
        try:
            WMS_KEYWORD = settings.KEYWORD_WMS
        except:
            WMS_KEYWORD = '_displacement_'
    VERSION_WMS = '1.1.1'  # owslib does not handle 1.3.0
    LAYER_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
    out = {}

    out['base_url'] = os.path.join(settings.SITEURL, 'geoserver/wms/')
    session_key = request.session.session_key
    date_start = request.GET.get('date_start', None)
    date_end = request.GET.get('date_end', None)
    get_capabilities_url = os.path.join(
        settings.SITEURL,
        'geoserver/ows?service=wms&version=%s&request=GetCapabilities' % VERSION_WMS)
    wms_request = urllib2.Request(get_capabilities_url)
    wms_request.add_header('sessionid', session_key)
    wms_request.add_header('Authorization', request.META.get('HTTP_COOKIE', ''))
    wms_request.add_header('cookie', request.META.get('HTTP_COOKIE', ''))
    wms_request.add_header('csrf-cookie', request.META.get('CSRF_COOKIE', ''))
    try:
        response = urllib2.urlopen(wms_request)
    except urllib2.HTTPError, error: 
        out['error'] = error.read() or 'Unable to connect to GeoServer'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    response_data = response.read()
    #return HttpResponse(response_data, mimetype="application/xhtml+xml", status=200)

    wms = WebMapService('url', version=VERSION, xml=response_data)
    layers = [wms[layer].name for layer in wms.contents]
    for layer in layers:
        if WMS_KEYWORD in layer or WMS_KEYWORD in wms[layer].keywords:
            out['layer_name'] = layer
            try:
                time_list = wms[layer].timepositions
            except:
                time_list = []
            if (date_start or date_end) and time_list:
                if not date_start:
                    date_start = time_list[0]
                if not date_end:
                    date_end = time_list[-1]
                try:
                    _time_list = []
                    _date_start = datetime.datetime.strptime(
                        date_start, LAYER_DATE_FORMAT)
                    _date_end = datetime.datetime.strptime(
                        date_end, LAYER_DATE_FORMAT)
                    _date_times = [
                        datetime.datetime.strptime(s, LAYER_DATE_FORMAT) \
                            for s in time_list]
                    for _date in _date_times:
                        if _date <= _date_end and _date >= _date_start:
                            _d = _date.strftime("%Y-%m-%dT%H:%M:%S.%f")
                            _time_list.append("%sZ" % _d[:-3])  # round to 3 dec
                    time_list = _time_list
                except:
                    pass
            out['date_indices'] = time_list
    # results
    if data_format == 'json':
        return HttpResponse(
                json.dumps(out),
                mimetype='application/json',
                status=200)
    else:
        return HttpResponse(
                json.dumps({'Error': 'Incorrect format'}),
                mimetype='application/json',
                status=400)

    
@ajax_login_required
def wfs_layer_metadata(request, data_format='json', keyword=None)):
    """Return JSON-formatted metadata for a WFS layer(s) for a previously
    authenticated user.
    
    A keyword is used to filter for the required layer(s)
    
    Results:
        {"date_field": "observed_date", 
         "base_url": "http://server.co.za:1080/geoserver/wfs/", 
         "layer_name": "deformation_features_test"}
    """
     if keyword:
        WFS_KEYWORD = keyword
    else:
        try:
            WFS_KEYWORD = settings.KEYWORD_WFS
        except:
            WFS_KEYWORD = 'deformation_features'
    VERSION_WFS = '1.0.0'
    out = {}
    out['base_url'] = os.path.join(settings.SITEURL, 'geoserver/wfs/')
    out['date_field'] = 'observed_date'
    get_capabilities_url = os.path.join(
        settings.SITEURL,
        'geoserver/ows?service=wfs&version=%s&request=GetCapabilities' % VERSION_WFS)
    session_key = request.session.session_key
    wfs_request = urllib2.Request(get_capabilities_url)
    wfs_request.add_header('sessionid', session_key)
    wfs_request.add_header('Authorization', request.META.get('HTTP_COOKIE', ''))
    wfs_request.add_header('cookie', request.META.get('HTTP_COOKIE', ''))
    wfs_request.add_header('csrf-cookie', request.META.get('CSRF_COOKIE', ''))
    try:
        response = urllib2.urlopen(wfs_request)
    except urllib2.HTTPError, error: 
        out['error'] = error.read() or 'Unable to connect to GeoServer'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    data = response.read()
    #return HttpResponse(data, mimetype="application/xhtml+xml",status=200)

    wfs = WebFeatureService('url', version=VERSION, xml=data)
    for layer in wfs.contents:
        _keywords_list = wfs[layer].keywords[0].split(',')
        keywords_list = [key.strip() for key in _keywords_list]
        if WFS_KEYWORD in layer or WFS_KEYWORD in keywords_list:
            out['layer_name'] = layer
    # results
    if data_format == 'json':
        return HttpResponse(
                json.dumps(out),
                mimetype='application/json',
                status=200)
    else:
        return HttpResponse(
                json.dumps({'Error': 'Incorrect format'}),
                mimetype='application/json',
                status=400)
