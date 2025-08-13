import re
from .utils.slack_notifier import send_slack_alert
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
# from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status
from .models import ModerationRequest, ModerationResult
from django.contrib.auth.hashers import make_password, check_password
from .serializers import UserSerializer
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.messages import HumanMessage
import base64
import json
import hashlib
import os
from dotenv import load_dotenv
from django.db.models import Count, Avg

load_dotenv()

api = os.getenv("API_KEY")
print("API: ", api)

User = get_user_model()

template = """You are a content moderation AI. Analyze the following content and classify it.

Content: {content}

You MUST respond with ONLY a valid JSON object. Do not include any other text, explanation, or formatting.

Required format:
{{"category": "toxic|spam|harassment|nudity|safe", "confidence": 0.0-1.0, "reason": "explanation"}}

Examples of correct responses:
{{"category": "toxic", "confidence": 0.92, "reason": "Contains offensive language"}}
{{"category": "safe", "confidence": 0.95, "reason": "No harmful content detected"}}
{{"category": "spam", "confidence": 0.78, "reason": "Promotional content detected"}}

JSON Response:"""


class modelHandler:
    def __init__(self, model="gemini-2.5-flash"):
        self.model = model
        self.llm = ChatGoogleGenerativeAI(
            google_api_key=api,
            model=self.model,
            temperature=0.7,
            max_tokens=None,
            timeout=None,
            max_retries=5
        )

        self.prompt = PromptTemplate(
            input_variable=["content"],
            template=template
        )


class Register_and_Login(viewsets.ViewSet):

    @action(detail=False, permission_classes=[AllowAny])
    def userRegister(self, request):

        name = request.data.get('name')
        phone = request.data.get('phone')
        email = request.data.get('email')
        password = request.data.get('password')

        if not all([name, phone, email, password]):
            return Response({"error": "Please enter all fields"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User already exists"}, status=status.HTTP_409_CONFLICT)

        hashPass = make_password(password=password)
        user = User.objects.create(name=name, phone=phone, email=email, password=hashPass)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, permission_classes=[AllowAny])
    def userLogin(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Please enter valid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = User.objects.get(email=email)
            if check_password(password, user.password):
                refresh = RefreshToken.for_user(user)
                serializer = UserSerializer(user)
                return Response({"user": serializer.data, "refresh": str(refresh), "access": str(refresh.access_token)}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Incorrect password"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class Logout(viewsets.ViewSet):

    @action(detail=False, permission_classes=[IsAuthenticated])
    def userlogout(self, request):
        refresh_token = request.data.get('refreshToken')
        print(refresh_token)

        if not refresh_token:
            return Response({"error": "Refresh token is missing"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            log_status = token.blacklist()
            print("logged out successfully" if log_status else "Getting error while logout")
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


def extract_fallback_values(raw_response):
    """Extract moderation values from non-JSON response"""
    response_lower = raw_response.lower()

    # Extract category
    category = "unknown"
    if "toxic" in response_lower:
        category = "toxic"
    elif "spam" in response_lower:
        category = "spam"
    elif "harassment" in response_lower:
        category = "harassment"
    elif "safe" in response_lower:
        category = "safe"

    confidence_match = re.search(r'confidence[:\s]*([0-9.]+)', response_lower)
    confidence = float(confidence_match.group(1)) if confidence_match else 0.5

    # Use first sentence as reason
    reason = raw_response.split('.')[0][:100] if raw_response else "No reason provided"

    return {
        "category": category,
        "confidence": confidence,
        "reason": reason,
        "parsed_from_raw": True
    }


class ModerationSystem(viewsets.ViewSet):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'])
    def moderationModel(self, request):
        user = request.data.get('email')
        user_text = request.data.get('text')
        uploaded_file = request.FILES.get('file')

        content_type = "mixed" if user_text and uploaded_file else "text" if user_text else "image"

        content_data = (user_text or "").encode()

        if uploaded_file:
            content_data += uploaded_file.read()

        content_hash = hashlib.sha256(content_data).hexdigest()
        print(f"Debug content_hash: {content_hash}")

        try:
            get_email = User.objects.get(email=user)
        except get_email.DoesNotExist:
            print(f"User not exist{get_email}")

        # save to request_table
        moderation_request = ModerationRequest.objects.create(
            user=get_email,
            content_type=content_type,
            content_hash=content_hash,
            status="processing"
        )

        print(f"User: {request.user.email}")
        print(f"Text: {user_text}")
        if uploaded_file:
            print(f"File uploaded: {uploaded_file.name}")

        # create a modelHandler instance
        moderation_model = modelHandler()

        textPrompt = moderation_model.prompt.format(
            content=user_text if user_text else "No text provided"
        )

        message_content = [{"type": "text", "text": textPrompt}]

        image_content = ""
        if uploaded_file:
            file_bytes = uploaded_file.read()
            image_content = f"data:image/jpeg;base64,{base64.b64encode(file_bytes).decode('utf-8')}"
            print(f"Debug Image_content: {image_content}")

        if image_content:
            message_content.append({"type": "image_url", "image_url": image_content})
            print(f"Debug Message Content: {message_content}")

        message = HumanMessage(content=message_content)

        try:

            model_response = moderation_model.llm.invoke([message])
            raw_content = model_response.content.strip()

            clean_response = raw_content

            if clean_response.startswith('```json'):
                clean_response = clean_response.replace(
                    '```json', '').replace('```', '').strip()
            elif clean_response.startswith('```'):
                clean_response = clean_response.replace('```', '').strip()

            json_match = re.search(r'\{.*\}', clean_response, re.DOTALL)
            if json_match:
                cleaned_response = json_match.group(0)

            try:
                result_json = json.loads(cleaned_response)
                print("Successfully parsed JSON:", result_json)
            except json.JSONDecodeError:
                print("JSON parsing failed, using fallback extraction")
                result_json = extract_fallback_values(raw_content)

            ModerationResult.objects.create(
                request=moderation_request,
                classification=result_json["category"],
                confidence=float(result_json["confidence"]),
                reasoning=result_json["reason"],
                llm_response=model_response.content
            )

            moderation_request.status = "completed"
            moderation_request.save()

            inappropriate_labels = ["toxic", "harassment", "nudity", "hate"]
            if result_json["category"].lower() in inappropriate_labels:
                send_slack_alert(
                    user_email=request.user.email,
                    category=result_json["category"],
                    confidence=result_json["confidence"],
                    reason=result_json["reason"]
                )

            return Response({
                "moderation_result": result_json
            }, status=status.HTTP_200_OK)

        except Exception as e:
            moderation_request.status = "failed"
            moderation_request.save()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Analytics(viewsets.ViewSet):

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated], authentication_classes=[JWTAuthentication])
    def getAnalytics(self, request):

        requested_email = request.query_params.get('user')

        if not requested_email:
            return Response({"error": "Email query parameter 'user' is required"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            get_user = User.objects.get(email=requested_email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        get_requests = ModerationRequest.objects.filter(user=get_user)

        get_results = ModerationResult.objects.filter(request__in=get_requests)

        if not get_results.exists():
            return Response({
                "user": requested_email,
                "total_requests": 0,
                "category_counts": {},
                "average_confidence": 0,
                "last_activity": None
            }, status=status.HTTP_200_OK)

        category_counts_qs = get_results.values(
            "classification").annotate(count=Count("classification"))
        category_counts = {item["classification"]: item["count"] for item in category_counts_qs}

        avg_conf = get_results.aggregate(avg_conf=Avg("confidence"))["avg_conf"] or 0

        last_request = get_requests.order_by("-created_at").first()
        last_activity = last_request.created_at if last_request else None

        return Response({
            "user": requested_email,
            "total_requests": get_results.count(),
            "category_counts": category_counts,
            "average_confidence": round(avg_conf, 2),
            "last_activity": last_activity
        }, status=status.HTTP_200_OK)
