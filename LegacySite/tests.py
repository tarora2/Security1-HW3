from django.test import Client
from django.db import connection
from LegacySite.models import User, Product, Card
from django.test import TestCase
import time
import json

# Create your tests here.
# Please view: https://docs.djangoproject.com/en/3.2/topics/testing/overview/

class DjangoTestCase(TestCase):
    def setUp(self):
        User.objects.create(username="tu", password="tuss")
        User.objects.create(username="ar", password="arss")

        Product.objects.create(product_name="Columbia_Apparel Card 1", product_image_path="/images/product_7.jpg",
                                                           recommended_price="80", description="Stocks")

# 1- Write the test confirming XSS vulnerability is fixed
    def test_xss_attack(self):
        c2 = Client()
        response = c2.post('/register', {'uname': 'test', 'pword': 'test', 'pword2': 'test'})
        res = c2.post('/login', {'uname': 'test', 'pword': 'test'}, follow=True)
        res = c2.get('/buy.html?director=<script>alert("hacked")</script>')
        # print(res.content)
        resp = res.content;
        check = False
        temp = '&lt;script&gt;alert(&quot;hacked&quot;)&lt;'
        if (temp in str(resp)):
            check = True

        assert(check == True)
        # hacked = False;
        # if "hacked" in str(res.content):
        #     print("check")
        # print (res.content)

# 2- Write the test confirming CSRF vulnerability is fixed

    def test_csrf_attack(self):
        # A registered user sends not his card to another user
        c = Client(enforce_csrf_checks=True)
        c.post('/register', {'uname': 'tus', 'pword': 'tusss', 'pword2': 'tusss'})
        c.post('/login', {'uname': 'tus', 'pword': 'tusss'})
        Product.objects.create(product_name="Columbia_Apparel Card 2", product_image_path="/images/product_8.jpg",
                               recommended_price="80", description="Stocks")
        data = {'amount': '80', 'username': 'ar'}

        response = c.post("/gift.html", data)
        assert(response.status_code != 200)

        # A non-registered user sends a card to another user - like u mentioned in post # 482
        c1 = Client(enforce_csrf_checks=True)
        Product.objects.create(product_name="Columbia_Apparel Card 3", product_image_path="/images/product_9.jpg",
                               recommended_price="70", description="Stocks")
        data = {'amount': '70', 'username': 'tu'}
        response2 = c1.post("/gift.html", data)
        assert(response2.status_code != 200)


# # 3- Write the test confirming SQL Injection attack is fixed

    def test_sql_attack(self):
        c2 = Client()
        response = c2.post('/register', {'uname': 'tujs', 'pword': 'tusss', 'pword2': 'tusss'})
        res = c2.post('/login', {'uname': 'tujs', 'pword': 'tusss'}, follow=True)
        # print(res.redirect_chain)
        # print(res.context)
        content = ''
        check = False
        with open('LegacySite/newcard.gftcrd', 'rb') as fp:
            resp = c2.post('/use.html', {'card_supplied': True, 'card_fname': 'fred', 'card_data': fp})
            print ("Checking the status code: ", resp.status_code)
            content = resp.content
            # print(content)
        # checking only a part of the hashed password just to make sure that the test is running
        password = '0000000000000000000000000'
        if (password in str(content)):
            check = True

        assert(check == False)
