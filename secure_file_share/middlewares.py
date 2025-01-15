from django.http import JsonResponse

class CorsOptionsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # If the request is an OPTIONS request, return an empty response with appropriate headers
        if request.method == "OPTIONS":
            response = JsonResponse({"message": "CORS preflight successful"}, status=200)
            response["Access-Control-Allow-Origin"] = "http://localhost:5173"  # Frontend origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response["Access-Control-Allow-Headers"] = "content-type, authorization, x-csrftoken"
            return response

        # For other requests, pass them to the next middleware/view
        response = self.get_response(request)
        return response
