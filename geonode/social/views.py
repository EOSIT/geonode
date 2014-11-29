from actstream.models import Action
from django.views.generic import ListView
from django.conf import settings


class RecentActivity(ListView):
    """
    Returns recent public activity.
    """
    context_object_name = 'action_list'
    #queryset = Action.objects.filter(public=True)[:15]
    template_name = 'social/activity_list.html'

    def get_context_data(self, *args, **kwargs):
        context = super(ListView, self).get_context_data(*args, **kwargs)
        context['action_list_layers'] = self.get_action('layer')
        context['action_list_maps'] = self.get_action('map')
        context['action_list_comments'] = self.get_action('comment')
        return context

    def get_action(self, name):
        if settings.LOCKDOWN_GROUP_PROFILE:
            if self.request.user.is_staff:
                return Action.objects.filter(
                    public=True,
                    action_object_content_type__name=name)[:15]
            else:
                return Action.objects.filter(
                    public=True,
                    user=self.request.user,
                    action_object_content_type__name=name)[:15]
        return Action.objects.filter(
            public=True,
            action_object_content_type__name=name)[:15]

    def get_queryset(self):
        if settings.LOCKDOWN_GROUP_PROFILE:
            if self.request.user.is_staff:
                return Action.objects.filter(public=True)[:15]
            else:
                return Action.objects.filter(public=True, user=self.request.user)[:15]
        return Action.objects.filter(public=True)[:15]