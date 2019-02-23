import os
import jinja2

# Helper library for other files to use
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def jinja_render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
