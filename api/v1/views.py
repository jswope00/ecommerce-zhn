# -*- coding:utf-8 -*-
from __future__ import unicode_literals, absolute_import

import json
import thread
import logging
import requests

from django.http import HttpResponseRedirect, HttpResponse
from rest_framework.views import APIView
from payments.alipay.alipay import notify_verify
from payments.alipay.app_alipay import AlipayAppVerify
from payments.wechatpay.wxapp_pay import Wxpay_server_pub as AppWxpay_server_pub
from payments.wechatpay.wxpay import Wxpay_server_pub
from payments.wechatpay.wxh5_pay import WxpayH5_server_pub
from payments.alipay.config import ALIPAYSettings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import ensure_csrf_cookie
from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
import subprocess
import qrcode
import base64
import cStringIO
import copy

# 需要放在安全区的变量
dish = 0
lock = thread.allocate_lock()
log = logging.getLogger(__name__)

########################
from django.core.exceptions import MultipleObjectsReturned
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils.six import StringIO
from django.views.generic import View
from oscar.apps.partner import strategy
from oscar.apps.payment.exceptions import PaymentError
from oscar.core.loading import get_class, get_model
from requests.exceptions import Timeout

from ecommerce.core.url_utils import get_lms_url
from ecommerce.extensions.basket.utils import basket_add_organization_attribute
from ecommerce.extensions.checkout.mixins import EdxOrderPlacementMixin
from ecommerce.extensions.checkout.utils import get_receipt_page_url
from ecommerce.extensions.payment.helpers import get_processor_class_by_name

logger = logging.getLogger(__name__)

Applicator = get_class('offer.applicator', 'Applicator')
Basket = get_model('basket', 'Basket')
BillingAddress = get_model('order', 'BillingAddress')
Country = get_model('address', 'Country')
NoShippingRequired = get_class('shipping.methods', 'NoShippingRequired')
OrderNumberGenerator = get_class('order.utils', 'OrderNumberGenerator')
OrderTotalCalculator = get_class('checkout.calculators', 'OrderTotalCalculator')
PaymentProcessorResponse = get_model('payment', 'PaymentProcessorResponse')
########################


class AlipaySuccessAPIView(APIView):
    """
    alipay success api view
    """

    def get(self, request, *args, **kwargs):
        """
        create order
        ---
        支付宝支付 同步
        GET传递参数 同步
            1.用户在登录成功后会看到一个支付宝提示登录的页面，该页面会停留几秒，然后会自动跳转回商户指定的同步通知页面（参数return_url）。
            2.该页面中获得参数的方式，需要使用GET方式获取，如request.QueryString(“out_trade_no”)、$_GET[‘out_trade_no’]。后续商户可根据获取的信息作处理，譬如，可以把获取到的token放入session中，以便于后续需要使用到token访问支付宝相应服务时，可以便捷地重用。
            3.该方式仅仅在用户登录完成以后进行自动跳转，因此只会进行一次。
            4.该方式不是支付宝主动去调用商户页面，而是支付宝的程序利用页面自动跳转的函数，使用户的当前页面自动跳转。
            5.该方式可在本机而不是只能在服务器上进行调试。
            6.返回URL只有一分钟的有效期，超过一分钟该链接地址会失效，验证则会失败。
            7.设置页面跳转同步通知页面（return_url）的路径时，不要在页面文件的后面再加上自定义参数。
            8.由于支付宝会对页面跳转同步通知页面（return_url）的域名进行合法有效性校验，因此设置页面跳转同步通知页面（return_url）的路径时，不要设置成本机域名，也不能带有特殊字符（如“!”），如：买家付款成功后，如果接口中指定有return_url,买家付完款后会调到return_url所在的页面。 这个页面可以展示给客户看。这个页面只有付款成功后才会跳转。
        """

        global lock, dish
        log.info('************ alipay query params ************')
        if notify_verify(request.query_params):
            out_trade_no = request.query_params.get("out_trade_no", "")
            extra_common_param = request.query_params.get("extra_common_param")

            post_data = {
                "trade_type": "alipay",
                'out_trade_no': out_trade_no,
                "total_fee": request.query_params.get("total_fee"),
                "original_data": json.dumps({'data': request.query_params}),
            }
            url_str = ALIPAYSettings.PAY_RESULT_URL + "?out_trade_no=" + out_trade_no
            if out_trade_no != "":
                rep = requests.post(extra_common_param, data=post_data)
                rep_data = rep.json()
                if rep_data.get('result') == "success":
                    return HttpResponseRedirect(url_str)
                return HttpResponseRedirect(url_str)
            else:
                return HttpResponseRedirect(url_str)
        else:
            return HttpResponse("fail")


class AlipayAsyncnotifyAPIView(APIView):
    """
    alipay asyncnotify api view
    """

    def post(self, request, *args, **kwargs):
        """
        支付宝支付 异步
        服务器后台通知，买家付完款后，支付宝会调用notify_url这个页面所在的页面，并把相应的参数传递到这个页面，
        这个页面根据支付宝传递过来的参数修改网站订单的状态。
        更新完订单后需要在页面上打印一个success给支付宝，如果反馈给支付宝的不是success,支付宝会继续调用这个页面。
        传递过来的参数是post格式
        商户需要验证该通知数据中的out_trade_no是否为商户系统中创建的订单号，
        并判断total_fee是否确实为该订单的实际金额（即商户订单创建时的金额），
        同时需要校验通知中的seller_id（或者seller_email) 是否为out_trade_no这笔单据的对应的操作方，
        （有的时候，一个商户可能有多个seller_id/seller_email），
        上述有任何一个验证不通过，则表明本次通知是异常通知，务必忽略。
        在上述验证通过后商户必须根据支付宝不同类型的业务通知，正确的进行不同的业务处理，并且过滤重复的通知结果数据。
        在支付宝的业务通知中，只有交易通知状态为TRADE_SUCCESS或TRADE_FINISHED时，支付宝才会认定为买家付款成功。
        如果商户需要对同步返回的数据做验签，必须通过服务端的签名验签代码逻辑来实现。
        如果商户未正确处理业务通知，存在潜在的风险，商户自行承担因此而产生的所有损失。
        """

        try:
            log.info('************ alipay notify data ************')
            log.info(request.data)
            if notify_verify(request.data):
                extra_common_param = request.data.get("extra_common_param")
                out_trade_no = request.data.get("out_trade_no", "")

                post_data = {
                    "trade_type": "alipay",
                    'out_trade_no': out_trade_no,
                    "total_fee": request.data.get("total_fee"),
                    "original_data": json.dumps({'data': request.data}),
                }
                if out_trade_no != "":
                    rep = requests.post(extra_common_param, data=post_data)
                    rep_data = rep.json()
                    if rep_data.get('result') == "success":
                        return HttpResponse('success')
        except Exception, e:
            log.exception(e)
        return HttpResponse("fail")


class AppAlipayAsyncnotifyAPIView(APIView):

    def post(self, request, *args, **kwargs):
        """
        app alipay asyncnotify api view
        """
        try:
            log.info('************ alipay app notify data ************')
            log.info(request.data)
            verify_srv = AlipayAppVerify()
            verify_srv.saveData(request.data)
            if verify_srv.checkSign():
                passback_params = request.data.get("passback_params")
                out_trade_no = request.data.get("out_trade_no", "")
                post_data = {
                    "trade_type": "alipay_app",
                    "original_data": json.dumps({'data': request.data}),
                }
                if out_trade_no != "":
                    rep = requests.post(passback_params, data=post_data)
                    rep_data = rep.json()
                    if rep_data.get('result') == "success":
                        return HttpResponse('success')
        except Exception, e:
            log.exception(e)
        return HttpResponse("fail")

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return

class WechatAsyncnotifyAPIView(EdxOrderPlacementMixin, APIView):
    """
    wechat asyncnotify api view
    """
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
    error_url = "/checkout/error/"

    @property
    def payment_processor(self):
        wechat_payment_processor_class = get_processor_class_by_name("wechatpay")
        Wechat_Payment_Processor = wechat_payment_processor_class()
        return Wechat_Payment_Processor

    def post(self, request, *args, **kwargs):
        """
        微信回调支付
        """
        try:
            ret_str = 'FAIL'
            log.info('********** wechatpay notify **********')
            log.info(request.body)
            wxpay_server_pub = Wxpay_server_pub()  # NATIVE pay
            wxpay_server_pub.saveData(request.body)
            resp_trade_type = wxpay_server_pub.getData().get('trade_type')
            if resp_trade_type == "APP":
                wxpay_server_pub = AppWxpay_server_pub()
                wxpay_server_pub.saveData(request.body)
                trade_type = 'wechat_app'
            elif resp_trade_type == "NATIVE":
                trade_type = 'wechat'
            if wxpay_server_pub.checkSign():
                pay_result = wxpay_server_pub.getData()
                post_data = {
                    'trade_type': trade_type,
                    'out_trade_no': pay_result.get('out_trade_no'),
                    "total_fee": pay_result.get("total_fee"),
                    "original_data": json.dumps({'data': request.body}),
                }
                final_data = copy.deepcopy(pay_result)
                final_data.pop('bank_type')
                final_data.pop('cash_fee')
                final_data.pop('fee_type')
                final_data.pop('is_subscribe')
                final_data.pop('openid')
                final_data.pop('result_code')
                final_data.pop('return_code')
                final_data.pop('time_end')
                final_data.pop('total_fee')
                final_data.pop('trade_type')
                final_data.pop('sign')
                sign = wxpay_server_pub.getSign(final_data)
                final_data.update({'sign': sign})
                if pay_result.get('attach'):
                    log.info("============================PAY RESULTT========%s", self.arrayToXml(final_data))
                    basket = self._get_basket(pay_result.get('attach'))
                    log.info("=============BASKET=============%s", basket)
                    receipt_url = get_receipt_page_url(
                        order_number=basket.order_number,
                        site_configuration=basket.site.siteconfiguration,
                    )

                    log.info("========================THE RECEIPT URL IS=====================%s", receipt_url)

                    try:
                        with transaction.atomic():
                            try:
                                self.handle_payment(pay_result, basket)
                            except PaymentError:
                                #return redirect(error_url)
                                return HttpResponse(wxpay_server_pub.arrayToXml({'return_code': 'SUCCESS'}))
                    except:  # pylint: disable=bare-except
                        logger.exception('Attempts to handle payment for basket [%d] failed.', basket.id)
                        return redirect(receipt_url)

                    try:
                        shipping_method = NoShippingRequired()
                        shipping_charge = shipping_method.calculate(basket)
                        order_total = OrderTotalCalculator().calculate(basket, shipping_charge)
                        user = basket.owner
                        # Given a basket, order number generation is idempotent. Although we've already
                        # generated this order number once before, it's faster to generate it again
                        # than to retrieve an invoice number from PayPal.
                        order_number = basket.order_number

                        order = self.handle_order_placement(
                            order_number=order_number,
                            user=user,
                            basket=basket,
                            shipping_address=None,
                            shipping_method=shipping_method,
                            shipping_charge=shipping_charge,
                            billing_address=None,
                            order_total=order_total,
                            request=request
                        )
                        self.handle_post_order(order)
                        return HttpResponse(wxpay_server_pub.arrayToXml({'return_code': 'SUCCESS'}))

                    except Exception as e:  # pylint: disable=broad-except
                        logger.exception(self.order_placement_failure_msg, basket.id, e)
                        #return redirect(receipt_url)
                        return HttpResponse(wxpay_server_pub.arrayToXml({'return_code': 'SUCCESS'}))

                    return HttpResponse(wxpay_server_pub.arrayToXml({'return_code': 'SUCCESS'}))
                    rep = requests.post("https://api.mch.weixin.qq.com/pay/orderquery", data=self.arrayToXml(final_data))
                    #log.info("====================THE RESPONSE IS DICT ===================== %s", wxpay_server_pub.xmlToArray(rep.content))
                    #log.info("====================THE RESPONSE IS DICT ===================== %s", wxpay_server_pub.xmlToArray(rep.content).get('return_code'))
                    #rep_data = rep.json()
                    if wxpay_server_pub.xmlToArray(rep.content).get('return_code') == "SUCCESS":
                        ret_str = 'SUCCESS'
        except Exception, e:
            log.exception(e)
        return HttpResponse(wxpay_server_pub.arrayToXml({'return_code': ret_str}))

    def _get_basket(self, payment_id):
        """
        Retrieve a basket using a payment ID.
        Arguments:
            payment_id: payment_id received from PayPal.
        Returns:
            It will return related basket or log exception and return None if
            duplicate payment_id received or any other exception occurred.
        """
        try:
            basket = PaymentProcessorResponse.objects.get(
                processor_name=self.payment_processor.NAME,
                transaction_id=payment_id
            ).basket
            basket.strategy = strategy.Default()

            Applicator().apply(basket, basket.owner, self.request)

            basket_add_organization_attribute(basket, self.request.GET)
            return basket
        except MultipleObjectsReturned:
            logger.warning(u"Duplicate payment ID [%s] received from WeChat Payment.", payment_id)
            return None
        except Exception:  # pylint: disable=broad-except
            logger.exception(u"Unexpected error during basket retrieval while executing WeChat payment.")
            return None

    def xmlToArray(self, xml):
        """将xml转为array"""
        array_data = {}
        root = ET.fromstring(xml)
        for child in root:
            value = child.text
            array_data[child.tag] = value
        return array_data

    def arrayToXml(self, arr):
        """array转xml"""
        xml = ["<xml>"]
        for k, v in arr.iteritems():
            #xml.append("<{0}>{1}</{0}>".format(k, v))
            xml.append("<{0}><![CDATA[{1}]]></{0}>".format(k, v))
        xml.append("</xml>")
        return "".join(xml)

class WechatH5AsyncnotifyAPIView(APIView):
    """
    wechat H5 asyncnotify api view
    """

    def post(self, request, *args, **kwargs):
        """
        微信H5回调支付
        """
        wxpayh5_server_pub = WxpayH5_server_pub()
        wxpayh5_server_pub.saveData(request.body)
        log.error(request.body)
        ret_str = 'FAIL'

        if xpayh5_server_pub.checkSign():
            pay_result = wxpayh5_server_pub.getData()
            post_data = {
                'trade_type': 'wechat_h5',
                'trade_no': pay_result.get('transaction_id'),
                "total_fee": pay_result.get("total_fee"),
                'out_trade_no': pay_result.get('out_trade_no'),
                "original_data": json.dumps({'data': request.body}),
            }
            if pay_result.get('attach'):
                rep = requests.post(pay_result['attach'], data=post_data)
                rep_data = rep.json()
                if rep_data.get('result') == "success":
                    ret_str = 'SUCCESS'
        return HttpResponse(wxpayh5_server_pub.arrayToXml({'return_code': ret_str}))

class WeChatQRCodeView(APIView):

    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    def get(self, request, format=None):
        context = {
            'body': True,
            'lms_url': get_lms_url()
        }
        return render(request,'wechat_qr.html',context)

    def post(self, request, format=None):
        code_url = request.POST.get('code_url')
        total_fee = request.POST.get('total_fee')
        img = qrcode.make(code_url)
        buffer = cStringIO.StringIO()
        img.save(buffer, format="JPEG")
        qr_img = buffer.getvalue()
        qr_img_64 = "data:image/jpeg;base64,"+base64.b64encode(qr_img)
        context = {
            'img_64': qr_img_64,
            'total_fee': total_fee
        }
        return render(request,'wechat_qr.html',context)
