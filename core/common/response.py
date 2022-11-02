from rest_framework.response import Response


def return_error_response(msg, code=400, data=None):
    return Response(
        {
            "message": msg,
            "code": code,
            "status": code,
            "success": False,
            "data": data
        },
        status=code
    )


def response(status=True, code=200, data=None, extra={}):
    response_data = {
        "status": status,
        "code": code,
        **extra
    }
    if data is not None:
        response_data['data'] = data
    return Response(
        response_data
    )


def error_400_409(status=False,  data=[]):
    return response(status=status,  data=data)


def error_common(status=False,  data=None):
    return response(status=status, data=data)


def success_response(status=True,  data=None):
    return response(status=status, data=data)