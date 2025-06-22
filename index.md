---
layout: default
title: Home
---

# Lorem Ipsum
Lorem Ipsum.

{% if site.posts.size > 0 %}
## Blog Posts

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>
{% endif %}
