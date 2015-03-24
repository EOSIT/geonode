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
import sys
import logging
import shutil
import traceback
import urllib2
from owslib.wms import WebMapService, ServiceException
from owslib.wfs import WebFeatureService
import sys
import datetime
from subprocess import Popen, PIPE

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, HttpResponseRedirect, Http404, \
    HttpResponseServerError
from django.shortcuts import render_to_response
from django.conf import settings
from django.template import RequestContext
from django.utils.translation import ugettext as _
from django.utils import simplejson as json
from django.utils.html import escape
from django.views.decorators.csrf import csrf_exempt
from django.template.defaultfilters import slugify
from django.forms.models import inlineformset_factory
from django.db.models import F
from django.db import IntegrityError

from geonode.tasks.deletion import delete_layer
from geonode.services.models import Service
from geonode.layers.forms import LayerForm, LayerUploadForm, NewLayerUploadForm, LayerAttributeForm
from geonode.base.forms import CategoryForm
from geonode.layers.models import Layer, Attribute, UploadSession
from geonode.base.enumerations import CHARSETS
from geonode.base.models import TopicCategory

from geonode.utils import default_map_config
from geonode.utils import GXPLayer
from geonode.utils import GXPMap
from geonode.layers.utils import file_upload, is_raster, is_vector
from geonode.utils import resolve_object, llbbox_to_mercator
from geonode.people.forms import ProfileForm, PocForm
from geonode.people.models import Profile
from geonode.security.views import _perms_info_json
from geonode.documents.models import get_related_documents
from geonode.groups.models import GroupProfile
from geonode.utils import build_social_links
from geonode.geoserver.helpers import cascading_delete, gs_catalog

CONTEXT_LOG_FILE = None

if 'geonode.geoserver' in settings.INSTALLED_APPS:
    from geonode.geoserver.helpers import _render_thumbnail
    from geonode.geoserver.helpers import ogc_server_settings
    CONTEXT_LOG_FILE = ogc_server_settings.LOG_FILE

logger = logging.getLogger("geonode.layers.views")

DEFAULT_SEARCH_BATCH_SIZE = 10
MAX_SEARCH_BATCH_SIZE = 25
GENERIC_UPLOAD_ERROR = _("There was an error while attempting to upload your data. \
Please try again, or contact and administrator if the problem continues.")

_PERMISSION_MSG_DELETE = _("You are not permitted to delete this layer")
_PERMISSION_MSG_GENERIC = _('You do not have permissions for this layer.')
_PERMISSION_MSG_MODIFY = _("You are not permitted to modify this layer")
_PERMISSION_MSG_METADATA = _(
    "You are not permitted to modify this layer's metadata")
_PERMISSION_MSG_VIEW = _("You are not permitted to view this layer")


def log_snippet(log_file):
    if not os.path.isfile(log_file):
        return "No log file at %s" % log_file

    with open(log_file, "r") as f:
        f.seek(0, 2)  # Seek @ EOF
        fsize = f.tell()  # Get Size
        f.seek(max(fsize - 10024, 0), 0)  # Set pos @ last n chars
        return f.read()


def ajax_login_required(f):
    def wrap(request, *args, **kwargs):
        #if 'userid' not in request.session.keys():
        if not request.user.is_authenticated():
            out = {}
            out['error'] = 'Not logged in.'
            return HttpResponse(
                json.dumps(out),
                mimetype='application/json',
                status=400)
        return f(request, *args, **kwargs)
    wrap.__doc__=f.__doc__
    wrap.__name__=f.__name__
    return wrap


def get_csrf(request):
    # https://docs.djangoproject.com/en/1.6/ref/contrib/csrf/#how-to-use-it
    from django.middleware.csrf import get_token
    csrf_token = get_token(request)
    # OR
    # from django.core.context_processors import csrf
    # csrf_token = csrf(request)
    return HttpResponse(
        json.dumps(csrf_token),
        mimetype='application/json',
        status=200)


@csrf_exempt
def create_group(request):
    """Create a GeoNode Group from a JSON POST."""
    out = {}
    if request.method == 'GET':
        from django.middleware.csrf import get_token
        csrf_token = get_token(request)
        # OR
        # from django.core.context_processors import csrf
        # csrf_token = csrf(request)
        return HttpResponse(
            content=csrf_token,
            mimetype="text/plain",
            status=200)
    elif request.method == 'POST':
        if not request.user.is_authenticated():
            out['error'] = 'Not logged in'
        else:
            json_data = json.loads(request.body)
            title = json_data.get('title')
            slug = json_data.get('slug')
            description = json_data.get('description')
            access = json_data.get('access')
            #TODO - check that access is a 'legal' value (from GroupProfile)
            if title and description and access:
                # create group
                try:
                    group = GroupProfile()
                    group.title = title
                    if slug:
                        group.slug = slugify(slug)
                    else:
                        group.slug = slugify(title)
                    group.description = description
                    group.access = access
                    group.clean()
                    group.save()
                    out['group_id'] = group.id
                except IntegrityError:
                    out['error'] = 'That group already exists'
            else:
                out['error'] = 'Insufficient data to create group'
    else:
        pass
    return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=400)


def user_summary(request):
    """Return JSON-formatted metadata for either a parameterised user (uid)
    OR the current user.
    """
    from geonode.people.models import Profile
    out = {}
    if not request.user.is_authenticated():
        out['error'] = 'Not logged in.'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=400)
    user, user_groups, out = get_user_groups(request)
    try:
        orgs, groups = [], []
        for user_group in user_groups:
            orgs.append(user_group.description)
            groups.append(user_group.pk)
        uname = user.username
        profile = Profile.objects.get(username=uname)  # user.profile
        out['username'] = uname
        out['first_name'] = profile.first_name
        out['last_name'] = profile.last_name
        out['organization'] = orgs
        out['groups'] = groups
        out['position'] = profile.position
    except:
        out['error'] = 'Profile details not available.'
    return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=200)


@ajax_login_required
def get_user_groups(request, out={}):
    """Get groups for either a parameterised user (uid) OR the current user.

    Args:
        out: dictionary
            out is typically used when there is an API call that expects a
            JSON return.
    Returns:
        user, groups, out: tuple
            user - GeoNode user object
            groups - list of GeoNode group objects
            out -  dictionary
    """
    out['error'] = None
    try:
        reporter_group = settings.REPORTER_GROUP
    except AttributeError:
        print >>sys.stderr, "Unable to find REPORTER_GROUP in settings"
        out['error'] = 'The report setup is not configured properly.'
    if not out['error']:
        uid = request.GET.get('uid', None)
        if uid:
            # validate that current user is allowed access to groups
            # use the pre-created REPORTER_GROUP as the access mechanism
            request_user_groups = GroupProfile.groups_for_user(request.user)
            #print >>sys.stderr, "DEBUG:groups:reporter/user", reporter_group, '~', request_user_groups
            try:
                reporter_group_profile = GroupProfile.objects.get(
                    title=reporter_group)
            except ObjectDoesNotExist:
                reporter_group_profile = None
                out['error'] = 'Reporter group does not exist.'
            if reporter_group_profile in request_user_groups:
                try:
                    #print >>sys.stderr, "DEBUG:uid", uid
                    _user = Profile.objects.get(username=uid)
                    _user_groups = GroupProfile.groups_for_user(_user)
                    #print >>sys.stderr, "DEBUG:groups:uid", _user_groups
                    return _user , _user_groups, out
                except ObjectDoesNotExist:
                    out['error'] = 'User does not exist.'
            else:
                out['error'] = 'Access to user data denied.'
        else:
            request_user_groups = GroupProfile.groups_for_user(request.user)
            if not request_user_groups:
                out['error'] = 'User is not a member of any group.'
            #print >>sys.stderr, "DEBUG:groups:user", request.user, '~', request_user_groups
            return request.user, request_user_groups, out
    return None, [], out


def exec_external_cmd(cmd_line):
    retcode = None
    try:
        process = Popen(cmd_line, bufsize=2048, executable="/bin/bash",
                        shell=True, stdout=None, stderr=None)
        while retcode == None:
            retcode = process.poll()
        if retcode < 0:
            print >>sys.stderr, "Child was terminated by signal", retcode
        elif retcode > 0:
            print >>sys.stderr, "Child returned", retcode
    except OSError, e:
        print >>sys.stderr, "Execution failed:", e
    return retcode


@ajax_login_required
def run_report(request):
    try:
        output = settings.REPORTER_DIR
        script = settings.REPORTER_SCRIPT
        assert os.path.exists(output)
        assert os.path.exists(script)
    except AttributeError:
        print >>sys.stderr, "Unable to find REPORTER_DIR or REPORTER_SCRIPT in settings"
        return HttpResponseServerError(
            'The report setup is not configured properly.')
    except AssertionError:
        print >>sys.stderr, "Unable to find REPORTER_DIR or REPORTER_SCRIPT on file system"
        return HttpResponseServerError(
            'The report locations are not configured properly.')
    date_start = request.GET.get('date_start', None)
    date_end = request.GET.get('date_end', None)
    user, user_groups, out = get_user_groups(request)
    #print >>sys.stderr, "DEBUG:USER/GROUPS:", user, '~', user_groups, '~', out
    if user and user_groups and len(user_groups) >= 1:
        uid = user.username
        report_filename = '%s/%s.pdf' % (output, user_groups[0])
        cmd_line = 'phantomjs %s %s %s %s %s' % \
            (script, report_filename, uid, date_start or '', date_end or '')
        #print >>sys.stderr, "DEBUG:PJS", script, '~', report_filename, '~', uid, '~', date_start, '~', date_end
        rc = exec_external_cmd(cmd_line)
        try:
            with open(report_filename, 'r') as pdf:
                response = HttpResponse(pdf.read(), mimetype='application/pdf')
                response['Content-Disposition'] = \
                    'attachment; filename=subsidence_report.pdf'
                response['Content-Transfer-Encoding'] = 'binary'
                response['Cache-Control'] = \
                    'must-revalidate, post-check=0, pre-check=0'
                response['Pragma'] = 'public'
                response['Content-Length'] = os.stat(report_filename).st_size
                return response
            pdf.closed
        except:
            print >>sys.stderr, 'Return code: "%s" for report: "%s"' % \
                (rc, cmd_line)
            raise Http404('Unable to generate the report.')
    else:
        if out.get('error'):
            return HttpResponseServerError(out.get('error'))
        else:
            raise Http404('That user is invalid or is not a member of the report group.')


@ajax_login_required
def getcapabilities_layers(request):
    """The CAPABILITIES_CACHE file should contain JSON data in the form:
        layer_name: [dates,] where layer_name is composed of group & type.
    Example:
        {
        'meraka_deformation_features': [],
        'meraka_displacement_wgs84':  [
            "2014-09-07T00:00:00.000Z", "2014-10-01T00:00:00.000Z",
            "2014-10-25T00:00:00.000Z", "2014-11-18T00:00:00.000Z",
            "2014-12-12T00:00:00.000Z", "2015-01-05T00:00:00.000Z",
            "2015-01-29T00:00:00.000Z"]
        }
    """
    #TODO - this could be handled by a direct call to GeoServer?
    result = {}
    try:
        with open(settings.CAPABILITIES_CACHE) as json_data:
            result = json.load(json_data)
            return result
    except AttributeError:
        print >>sys.stderr, "Unable to find CAPABILITIES_CACHE in settings"
    except IOError:
        print >>sys.stderr, "Unable to load capabilities file"
    except json.scanner.JSONDecodeError:
        print >>sys.stderr, "Unable to decode capabilities data"
    return result


def _check_dates(time_list, layer_date_format, date_start=None, date_end=None):
    """Return list of date/time strings in ISO format (%Y-%m-%dT%H:%M:%S.%f)"""
    UI_DATE_FORMAT = "%Y-%m-%d"  #format expected from the web interface
    if (date_start or date_end) and time_list:
        if not date_start:
            date_start = time_list[0]
        if not date_end:
            date_end = time_list[-1]
        _time_list = []
        try:
            _date_start = datetime.datetime.strptime(
                date_start, UI_DATE_FORMAT)
            _date_end = datetime.datetime.strptime(
                date_end, UI_DATE_FORMAT)
            _date_times = [
                datetime.datetime.strptime(s, layer_date_format) \
                    for s in time_list]
        except ValueError, e:
            _date_times = []
            print >>sys.stderr, "Unable to parse dates: %s" % e
        for _date in _date_times:
            if _date <= _date_end and _date >= _date_start:
                _d = _date.strftime("%Y-%m-%dT%H:%M:%S.%f")
                _time_list.append("%sZ" % _d[:-3])  # round to 3 dec
        time_list = _time_list
    return time_list


def get_group_layers(request, out, user_groups, layer_type,
                     date_start, date_end):
    """
    Return a set of layers of specific type for a particular user group for a
    given date range from a custom capabilities list.

    Args:
        request: HTTP request
        out: dictionary
            Stores messages/data for return as JSON
        user_groups: list
            GeoNode Group objects
        layer_type: string
            One of: ['displacement' | 'features' | 'interferogram']
        date_start, date_end: strings
            "%Y-%m-%dT%H:%M:%S.%f"
    """
    try:
        LAYER_NAMESPACE = settings.LAYER_NAMESPACE
    except:
        print >>sys.stderr, "Unable to find LAYER_NAMESPACE in settings"
        LAYER_NAMESPACE = 'subsmon'
    try:
        LAYER_SUFFIXES = settings.LAYER_SUFFIXES
    except AttributeError:
        print >>sys.stderr, "Unable to find LAYER_SUFFIXES in settings"
        LAYER_SUFFIXES = ['_deformation_features', '_displacement_wgs84',
                          '_interferogram_wgs84']
    try:
        LAYER_DATE_FORMAT = settings.LAYER_DATE_FORMAT
    except AttributeError:
        print >>sys.stderr, "Unable to find LAYER_DATE_FORMAT in settings"
        LAYER_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
    layer_names = []
    for ug in user_groups:
        layer_names = ['%s:%s%s' % (LAYER_NAMESPACE, ug.slug, ls) \
            for ls in LAYER_SUFFIXES if layer_type not in ls]
    #print >>sys.stderr, "DEBUG:layer_names", layer_names

    capabilities = getcapabilities_layers(request)
    if not capabilities:
        print >>sys.stderr, "Capabilities do not exist or cannot be loaded."
        out['error'] = 'Capabilities do not exist or cannot be loaded.'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=404)
    else:
        for lyr in layer_names:
            dates = capabilities.get(lyr, [])
            if dates:
                formatted_dates = _check_dates(dates, LAYER_DATE_FORMAT,
                                               date_start, date_end)
                #print >>sys.stderr, "DEBUG:dates", formatted_dates
                if formatted_dates:
                    out["date_indices"] = formatted_dates
                    out["layer_name"] = lyr
                    return HttpResponse(
                        json.dumps(out),
                        mimetype='application/json',
                        status=200)
                else:
                     out['error'] = 'Unable to find or format %s dates in capabilities document' % layer_type
            else:
                out['error'] = 'No %s dates found in capabilities document' % layer_type

    return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=400)


@ajax_login_required
def displacement_map_time(request, date_start, date_end):
    """Return JSON-formatted metadata for the WMS data for a layer(s)
    where a time interval is specified.
    """
    return displacement_map(request, date_start=date_start, date_end=date_start)


@ajax_login_required
def displacement_interferogram(request):
    """Return JSON-formatted metadata for the WMS data for a layer(s)

    The _KEYWORD is used to filter for the correct type of layer(s)
    """
    #print >>sys.stderr, "DEBUG:interferogram view..."
    try:
        INTERFEROGRAM_KEYWORD = settings.INTERFEROGRAM_KEYWORD
    except:
        INTERFEROGRAM_KEYWORD = '_interferogram_'
    return wms_map_layer(request, INTERFEROGRAM_KEYWORD, 'interferogram')


@ajax_login_required
def displacement_map(request):
    """Return JSON-formatted metadata for the WMS data for a layer(s);

    The _KEYWORD is used to filter for the correct type of layer(s)
    """
    #print >>sys.stderr, "DEBUG:displacement view..."
    try:
        MAP_KEYWORD = settings.MAP_KEYWORD
    except:
        MAP_KEYWORD = '_displacement_'
    return wms_map_layer(request, MAP_KEYWORD, 'displacement')


@ajax_login_required
def wms_map_layer(request, key, layer_type):
    """Return JSON-formatted metadata for the WMS data for a layer(s);

    Args:
        key: string
            assigned to the LAYER_KEYWORD to filter for the correct type of
            layer(s); it can be overridden by a parameter in the request
        layer_type: string
            used to filter capabilities doc for the correct type of layer(s)
            see: get_group_layers()
    """
    #print >>sys.stderr, "DEBUG:wms_map view..."
    LAYER_KEYWORD = key
    VERSION = '1.1.1'  # owslib does not handle 1.3.0 (2014/10/20)
    LAYER_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # default
    out = {}
    out['base_url'] = os.path.join(settings.SITEURL, 'geoserver/wms/')
    session_key = request.session.session_key
    date_start = request.GET.get('date_start', None)
    date_end = request.GET.get('date_end', None)
    keyword = request.GET.get('keyword', None)
    if keyword:
        LAYER_KEYWORD = keyword
    #print >>sys.stderr, "DEBUG:session_key", session_key
    #print >>sys.stderr, "DEBUG:META", request.META
    get_capabilities_url = os.path.join(
        settings.SITEURL,
        'geoserver/ows?service=wms&VERSION=%s&request=GetCapabilities' % VERSION)
    user, user_groups, out = get_user_groups(request, out)
    #print >>sys.stderr, "DEBUG: user, user_groups", user, '~', user_groups
    if out.get('error'):
        return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=400)
    # if user in request parameter, then process via capabilities file
    if user:
        get_group_layers(request, out, user_groups, layer_type,
                        date_start, date_end)

    wms_request = urllib2.Request(get_capabilities_url)
    #print >>sys.stderr, "DEBUG:WMS request url:", get_capabilities_url
    wms_request.add_header('sessionid', session_key)
    wms_request.add_header('Authorization', request.META.get('HTTP_COOKIE', ''))
    wms_request.add_header('cookie', request.META.get('HTTP_COOKIE', ''))
    wms_request.add_header('csrf-cookie', request.META.get('CSRF_COOKIE', ''))
    try:
        response = urllib2.urlopen(wms_request)
    except urllib2.HTTPError, error:
        out['error'] = error or 'Unable to connect to GeoServer'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    #print >>sys.stderr, "DEBUG:response", response
    response_data = response.read()
    #print >>sys.stderr, "DEBUG:Caps-end", response_data[-1000:]
    try:
        wms = WebMapService('url', version=VERSION, xml=response_data)
    except ServiceException, error:
        out['error'] = error or 'Unable to connect to Web Map Service'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    #print >>sys.stderr, "DEBUG:wms.contents:", list(wms.contents)

    #for layer in wms.contents:
    #    print >>sys.stderr, "DEBUG:layer:", layer
    layers = [wms[layer].name for layer in wms.contents]
    #print >>sys.stderr, "layers:", layers
    for layer in layers:
        #print >>sys.stderr, "DEBUG:layer:keywords", layer, ':', wms[layer].keywords
        if LAYER_KEYWORD in layer or LAYER_KEYWORD in wms[layer].keywords:
            out['layer_name'] = layer
            #print >>sys.stderr, "DEBUG:layer_dict", wms[layer].__dict__
            #print >>sys.stderr, "DEBUG:layer_dict id",  wms[layer].__dict__.get('id'), wms[layer].__dict__.get('timepositions')
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
    status_code = 200
    return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=status_code)


@ajax_login_required
def displacement_features(request):
    """Return JSON-formatted metadata for the WFS data for a layer(s);

    The FEATURES_KEYWORD is used to filter for the correct layer(s); it can be
    over-ridden by a parameter in the request
    """
    #print >>sys.stderr, "DEBUG:wfs view..."
    try:
        FEATURES_KEYWORD = settings.FEATURES_KEYWORD
    except:
        FEATURES_KEYWORD = 'deformation_features'
    VERSION = '1.0.0'
    out = {}
    out['base_url'] = os.path.join(settings.SITEURL, 'geoserver/wfs/')
    out['date_field'] = 'observed_date'
    get_capabilities_url = os.path.join(
        settings.SITEURL,
        'geoserver/ows?service=wfs&version=%s&request=GetCapabilities' % VERSION)
    session_key = request.session.session_key
    date_start = request.GET.get('date_start', None)
    date_end = request.GET.get('date_end', None)
    keyword = request.GET.get('keyword', None)
    if keyword:
        FEATURES_KEYWORD = keyword

    user, user_groups, out = get_user_groups(request, out)
    #print >>sys.stderr, "DEBUG: user, user_groups", user, '~', user_groups
    if out.get('error'):
        return HttpResponse(
        json.dumps(out),
        mimetype='application/json',
        status=400)
    # if user specified as request parameter, then process via capabilities file
    if user:
        get_group_layers(request, out, user_groups, 'displacement',
                        date_start, date_end)

    wfs_request = urllib2.Request(get_capabilities_url)
    wfs_request.add_header('sessionid', session_key)
    wfs_request.add_header('Authorization', request.META.get('HTTP_COOKIE', ''))
    wfs_request.add_header('cookie', request.META.get('HTTP_COOKIE', ''))
    wfs_request.add_header('csrf-cookie', request.META.get('CSRF_COOKIE', ''))
    try:
        response = urllib2.urlopen(wfs_request)
    except urllib2.HTTPError, error:
        out['error'] = error or 'Unable to connect to GeoServer'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    data = response.read()
    try:
        wfs = WebFeatureService('url', version=VERSION, xml=data)
    except ServiceException, error:
        out['error'] = error or 'Unable to connect to Web Feature Service'
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=str(error.code))
    #print >>sys.stderr, "DEBUG:wfs.contents:", list(wfs.contents)

    for layer in wfs.contents:
        #print >>sys.stderr, "DEBUG:wfs layer:keywords", layer, wfs[layer].keywords
        _keywords_list = wfs[layer].keywords[0].split(',')
        keywords_list = [key.strip() for key in _keywords_list]
        #print >>sys.stderr, "DEBUG:wfs keywords list", keywords_list
        if FEATURES_KEYWORD in layer or FEATURES_KEYWORD in keywords_list:
            out['layer_name'] = layer
    # results
    status_code = 200
    return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=status_code)


def _resolve_layer(request, typename, permission='base.view_resourcebase',
                   msg=_PERMISSION_MSG_GENERIC, **kwargs):
    """
    Resolve the layer by the provided typename (which may include service name) and check the optional permission.
    """
    service_typename = typename.split(":", 1)
    service = Service.objects.filter(name=service_typename[0])

    if service.count() > 0:
        return resolve_object(request,
                              Layer,
                              {'service': service[0],
                               'typename': service_typename[1] if service[0].method != "C" else typename},
                              permission=permission,
                              permission_msg=msg,
                              **kwargs)
    else:
        return resolve_object(request,
                              Layer,
                              {'typename': typename,
                               'service': None},
                              permission=permission,
                              permission_msg=msg,
                              **kwargs)


# Basic Layer Views #


@login_required
def layer_upload(request, template='upload/layer_upload.html'):
    if request.method == 'GET':
        ctx = {
            'charsets': CHARSETS,
            'is_layer': True,
        }
        return render_to_response(template,
                                  RequestContext(request, ctx))
    elif request.method == 'POST':
        form = NewLayerUploadForm(request.POST, request.FILES)
        tempdir = None
        errormsgs = []
        out = {'success': False}

        if form.is_valid():
            title = form.cleaned_data["layer_title"]

            # Replace dots in filename - GeoServer REST API upload bug
            # and avoid any other invalid characters.
            # Use the title if possible, otherwise default to the filename
            if title is not None and len(title) > 0:
                name_base = title
            else:
                name_base, __ = os.path.splitext(
                    form.cleaned_data["base_file"].name)

            name = slugify(name_base.replace(".", "_"))

            try:
                # Moved this inside the try/except block because it can raise
                # exceptions when unicode characters are present.
                # This should be followed up in upstream Django.
                tempdir, base_file = form.write_files()
                saved_layer = file_upload(
                    base_file,
                    name=name,
                    user=request.user,
                    overwrite=False,
                    charset=form.cleaned_data["charset"],
                    abstract=form.cleaned_data["abstract"],
                    title=form.cleaned_data["layer_title"],
                )

            except Exception as e:
                exception_type, error, tb = sys.exc_info()
                logger.exception(e)
                out['success'] = False
                out['errors'] = str(error)
                # Assign the error message to the latest UploadSession from that user.
                latest_uploads = UploadSession.objects.filter(user=request.user).order_by('-date')
                if latest_uploads.count() > 0:
                    upload_session = latest_uploads[0]
                    upload_session.error = str(error)
                    upload_session.traceback = traceback.format_exc(tb)
                    upload_session.context = log_snippet(CONTEXT_LOG_FILE)
                    upload_session.save()
                    out['traceback'] = upload_session.traceback
                    out['context'] = upload_session.context
                    out['upload_session'] = upload_session.id
            else:
                out['success'] = True
                out['url'] = reverse(
                    'layer_detail', args=[
                        saved_layer.service_typename])

                upload_session = saved_layer.upload_session
                upload_session.processed = True
                upload_session.save()
                permissions = form.cleaned_data["permissions"]
                if permissions is not None and len(permissions.keys()) > 0:
                    saved_layer.set_permissions(permissions)

            finally:
                if tempdir is not None:
                    shutil.rmtree(tempdir)
        else:
            for e in form.errors.values():
                errormsgs.extend([escape(v) for v in e])

            out['errors'] = form.errors
            out['errormsgs'] = errormsgs

        if out['success']:
            status_code = 200
        else:
            status_code = 400
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=status_code)


def layer_detail(request, layername, template='layers/layer_detail.html'):
    layer = _resolve_layer(
        request,
        layername,
        'base.view_resourcebase',
        _PERMISSION_MSG_VIEW)
    # assert False, str(layer_bbox)
    config = layer.attribute_config()

    # Add required parameters for GXP lazy-loading
    layer_bbox = layer.bbox
    bbox = [float(coord) for coord in list(layer_bbox[0:4])]
    srid = layer.srid

    # Transform WGS84 to Mercator.
    config["srs"] = srid if srid != "EPSG:4326" else "EPSG:900913"
    config["bbox"] = llbbox_to_mercator([float(coord) for coord in bbox])

    config["title"] = layer.title
    config["queryable"] = True

    if layer.storeType == "remoteStore":
        service = layer.service
        source_params = {
            "ptype": service.ptype,
            "remote": True,
            "url": service.base_url,
            "name": service.name}
        maplayer = GXPLayer(
            name=layer.typename,
            ows_url=layer.ows_url,
            layer_params=json.dumps(config),
            source_params=json.dumps(source_params))
    else:
        maplayer = GXPLayer(
            name=layer.typename,
            ows_url=layer.ows_url,
            layer_params=json.dumps(config))

    # Update count for popularity ranking,
    # but do not includes admins or resource owners
    if request.user != layer.owner and not request.user.is_superuser:
        Layer.objects.filter(
            id=layer.id).update(popular_count=F('popular_count') + 1)

    # center/zoom don't matter; the viewer will center on the layer bounds
    map_obj = GXPMap(projection="EPSG:900913")
    NON_WMS_BASE_LAYERS = [
        la for la in default_map_config()[1] if la.ows_url is None]

    metadata = layer.link_set.metadata().filter(
        name__in=settings.DOWNLOAD_FORMATS_METADATA)

    context_dict = {
        "resource": layer,
        "permissions_json": _perms_info_json(layer),
        "documents": get_related_documents(layer),
        "metadata": metadata,
        "is_layer": True,
        "wps_enabled": settings.OGC_SERVER['default']['WPS_ENABLED'],
    }

    context_dict["viewer"] = json.dumps(
        map_obj.viewer_json(request.user, * (NON_WMS_BASE_LAYERS + [maplayer])))
    context_dict["preview"] = getattr(
        settings,
        'LAYER_PREVIEW_LIBRARY',
        'leaflet')

    if request.user.has_perm('download_resourcebase', layer.get_self_resource()):
        if layer.storeType == 'dataStore':
            links = layer.link_set.download().filter(
                name__in=settings.DOWNLOAD_FORMATS_VECTOR)
        else:
            links = layer.link_set.download().filter(
                name__in=settings.DOWNLOAD_FORMATS_RASTER)
        context_dict["links"] = links

    if settings.SOCIAL_ORIGINS:
        context_dict["social_links"] = build_social_links(request, layer)

    return render_to_response(template, RequestContext(request, context_dict))


@login_required
def layer_metadata(request, layername, template='layers/layer_metadata.html'):
    layer = _resolve_layer(
        request,
        layername,
        'base.change_resourcebase_metadata',
        _PERMISSION_MSG_METADATA)
    layer_attribute_set = inlineformset_factory(
        Layer,
        Attribute,
        extra=0,
        form=LayerAttributeForm,
    )
    topic_category = layer.category

    poc = layer.poc
    metadata_author = layer.metadata_author

    if request.method == "POST":
        layer_form = LayerForm(request.POST, instance=layer, prefix="resource")
        attribute_form = layer_attribute_set(
            request.POST,
            instance=layer,
            prefix="layer_attribute_set",
            queryset=Attribute.objects.order_by('display_order'))
        category_form = CategoryForm(
            request.POST,
            prefix="category_choice_field",
            initial=int(
                request.POST["category_choice_field"]) if "category_choice_field" in request.POST else None)
    else:
        layer_form = LayerForm(instance=layer, prefix="resource")
        attribute_form = layer_attribute_set(
            instance=layer,
            prefix="layer_attribute_set",
            queryset=Attribute.objects.order_by('display_order'))
        category_form = CategoryForm(
            prefix="category_choice_field",
            initial=topic_category.id if topic_category else None)

    if request.method == "POST" and layer_form.is_valid(
    ) and attribute_form.is_valid() and category_form.is_valid():
        new_poc = layer_form.cleaned_data['poc']
        new_author = layer_form.cleaned_data['metadata_author']
        new_keywords = layer_form.cleaned_data['keywords']

        if new_poc is None:
            if poc is None:
                poc_form = ProfileForm(
                    request.POST,
                    prefix="poc",
                    instance=poc)
            else:
                poc_form = ProfileForm(request.POST, prefix="poc")
            if poc_form.has_changed and poc_form.is_valid():
                new_poc = poc_form.save()

        if new_author is None:
            if metadata_author is None:
                author_form = ProfileForm(request.POST, prefix="author",
                                          instance=metadata_author)
            else:
                author_form = ProfileForm(request.POST, prefix="author")
            if author_form.has_changed and author_form.is_valid():
                new_author = author_form.save()

        new_category = TopicCategory.objects.get(
            id=category_form.cleaned_data['category_choice_field'])

        for form in attribute_form.cleaned_data:
            la = Attribute.objects.get(id=int(form['id'].id))
            la.description = form["description"]
            la.attribute_label = form["attribute_label"]
            la.visible = form["visible"]
            la.display_order = form["display_order"]
            la.save()

        if new_poc is not None and new_author is not None:
            new_keywords = layer_form.cleaned_data['keywords']
            layer.keywords.clear()
            layer.keywords.add(*new_keywords)
            the_layer = layer_form.save()
            the_layer.poc = new_poc
            the_layer.metadata_author = new_author
            Layer.objects.filter(id=the_layer.id).update(
                category=new_category
                )

            return HttpResponseRedirect(
                reverse(
                    'layer_detail',
                    args=(
                        layer.service_typename,
                    )))

    if poc is None:
        poc_form = ProfileForm(instance=poc, prefix="poc")
    else:
        layer_form.fields['poc'].initial = poc.id
        poc_form = ProfileForm(prefix="poc")
        poc_form.hidden = True

    if metadata_author is None:
        author_form = ProfileForm(instance=metadata_author, prefix="author")
    else:
        layer_form.fields['metadata_author'].initial = metadata_author.id
        author_form = ProfileForm(prefix="author")
        author_form.hidden = True

    return render_to_response(template, RequestContext(request, {
        "layer": layer,
        "layer_form": layer_form,
        "poc_form": poc_form,
        "author_form": author_form,
        "attribute_form": attribute_form,
        "category_form": category_form,
    }))


@login_required
def layer_change_poc(request, ids, template='layers/layer_change_poc.html'):
    layers = Layer.objects.filter(id__in=ids.split('_'))
    if request.method == 'POST':
        form = PocForm(request.POST)
        if form.is_valid():
            for layer in layers:
                layer.poc = form.cleaned_data['contact']
                layer.save()
            # Process the data in form.cleaned_data
            # ...
            # Redirect after POST
            return HttpResponseRedirect('/admin/maps/layer')
    else:
        form = PocForm()  # An unbound form
    return render_to_response(
        template, RequestContext(
            request, {
                'layers': layers, 'form': form}))


@login_required
def layer_replace(request, layername, template='layers/layer_replace.html'):
    layer = _resolve_layer(
        request,
        layername,
        'base.change_resourcebase',
        _PERMISSION_MSG_MODIFY)

    if request.method == 'GET':
        ctx = {
            'charsets': CHARSETS,
            'layer': layer,
            'is_featuretype': layer.is_vector(),
            'is_layer': True,
        }
        return render_to_response(template,
                                  RequestContext(request, ctx))
    elif request.method == 'POST':

        form = LayerUploadForm(request.POST, request.FILES)
        tempdir = None
        out = {}

        if form.is_valid():
            try:
                tempdir, base_file = form.write_files()
                if layer.is_vector() and is_raster(base_file):
                    out['success'] = False
                    out['errors'] = _("You are attempting to replace a vector layer with a raster.")
                elif (not layer.is_vector()) and is_vector(base_file):
                    out['success'] = False
                    out['errors'] = _("You are attempting to replace a raster layer with a vector.")
                else:
                    # delete geoserver's store before upload
                    cat = gs_catalog
                    cascading_delete(cat, layer.typename)
                    saved_layer = file_upload(
                        base_file,
                        name=layer.name,
                        user=request.user,
                        overwrite=True,
                        charset=form.cleaned_data["charset"],
                    )
                    out['success'] = True
                    out['url'] = reverse(
                        'layer_detail', args=[
                            saved_layer.service_typename])
            except Exception as e:
                out['success'] = False
                out['errors'] = str(e)
            finally:
                if tempdir is not None:
                    shutil.rmtree(tempdir)
        else:
            errormsgs = []
            for e in form.errors.values():
                errormsgs.append([escape(v) for v in e])

            out['errors'] = form.errors
            out['errormsgs'] = errormsgs

        if out['success']:
            status_code = 200
        else:
            status_code = 400
        return HttpResponse(
            json.dumps(out),
            mimetype='application/json',
            status=status_code)


@login_required
def layer_remove(request, layername, template='layers/layer_remove.html'):
    layer = _resolve_layer(
        request,
        layername,
        'base.delete_resourcebase',
        _PERMISSION_MSG_DELETE)

    if (request.method == 'GET'):
        return render_to_response(template, RequestContext(request, {
            "layer": layer
        }))
    if (request.method == 'POST'):
        try:
            delete_layer.delay(object_id=layer.id)
        except Exception as e:
            message = '{0}: {1}.'.format(_('Unable to delete layer'), layer.typename)

            if 'referenced by layer group' in getattr(e, 'message', ''):
                message = _('This layer is a member of a layer group, you must remove the layer from the group '
                            'before deleting.')

            messages.error(request, message)
            return render_to_response(template, RequestContext(request, {"layer": layer}))
        return HttpResponseRedirect(reverse("layer_browse"))
    else:
        return HttpResponse("Not allowed", status=403)


def layer_thumbnail(request, layername):
    if request.method == 'POST':
        layer_obj = _resolve_layer(request, layername)
        try:
            image = _render_thumbnail(request.body)

            if not image:
                return
            filename = "layer-%s-thumb.png" % layer_obj.uuid
            layer_obj.save_thumbnail(filename, image)

            return HttpResponse('Thumbnail saved')
        except:
            return HttpResponse(
                content='error saving thumbnail',
                status=500,
                mimetype='text/plain'
            )
