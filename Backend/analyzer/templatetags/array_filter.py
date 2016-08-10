from django import template
register = template.Library()

@register.filter
def is_string(val):
    return isinstance(val, basestring)
