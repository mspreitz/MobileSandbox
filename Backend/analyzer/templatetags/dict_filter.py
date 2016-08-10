from django import template
register = template.Library()

@register.filter()
def is_dict(val):
    return isinstance(val, dict)
