# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from . import __version__ as app_version

app_name = "oauth2_client"
app_title = "OAuth2 Client"
app_publisher = "Revant Nandgaonkar"
app_description = "OAuth 2.0 Client for frappe framework apps"
app_icon = "fa fa-cloud"
app_color = "#B784A7"
app_email = "revant.one@gmail.com"
app_license = "MIT"

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/oauth2_client/css/oauth2_client.css"
# app_include_js = "/assets/oauth2_client/js/oauth2_client.js"

# include js, css files in header of web template
# web_include_css = "/assets/oauth2_client/css/oauth2_client.css"
# web_include_js = "/assets/oauth2_client/js/oauth2_client.js"

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
#	"Role": "home_page"
# }

# Website user home page (by function)
# get_website_user_home_page = "oauth2_client.utils.get_home_page"

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Installation
# ------------

# before_install = "oauth2_client.install.before_install"
# after_install = "oauth2_client.install.after_install"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "oauth2_client.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
#	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"oauth2_client.tasks.all"
# 	],
# 	"daily": [
# 		"oauth2_client.tasks.daily"
# 	],
# 	"hourly": [
# 		"oauth2_client.tasks.hourly"
# 	],
# 	"weekly": [
# 		"oauth2_client.tasks.weekly"
# 	]
# 	"monthly": [
# 		"oauth2_client.tasks.monthly"
# 	]
# }

# Testing
# -------

# before_tests = "oauth2_client.install.before_tests"

# Overriding Whitelisted Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "oauth2_client.event.get_events"
# }

