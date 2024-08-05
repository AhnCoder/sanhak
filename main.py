import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
import random
import string
import requests
import json
import os
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText
from sdk.api.message import Message
from sdk.exceptions import CoolsmsException
from database import SessionLocal, Base, engine
from models import User, AuthPhone, AuthToken
from dotenv import load_dotenv
import logging
import pytz

# .env 파일의 환경 변수를 로드합니다.
load_dotenv()

# 환경 변수에서 API_KEY, API_SECRET, SENDER_NUMBER, JWT_SECRET_KEY, JWT_ALGORITHM를 가져옵니다.
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
SENDER_NUMBER = os.getenv("SENDER_NUMBER")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")

app = FastAPI()

# 데이터베이스 테이블 생성 (필요한 경우에만 사용)
Base.metadata.create_all(bind=engine)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 서울 시간대 설정
KST = pytz.timezone("Asia/Seoul")

class PhoneNumberRequest(BaseModel):
    phone_number: str

class VerifyCodeRequest(BaseModel):
    phone_number: str
    auth_code: str

class UserSignupRequest(BaseModel):
    student_number: str
    name: str
    email: str
    contact: str
    department: str

def generate_verification_code(length=6):
    return "".join(random.choices(string.digits, k=length))

def create_access_token(student_number: str):
    expire = datetime.utcnow() + timedelta(hours=1)
    payload = {"sub": student_number, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/send_sms/")
def send_sms(request: PhoneNumberRequest, db: Session = Depends(get_db)):
    verification_code = generate_verification_code()
    expires_at_kst = datetime.now(tz=KST) + timedelta(minutes=5)

    auth_phone = AuthPhone(
        phone_number=request.phone_number,
        auth_code=verification_code,
        expires_at=expires_at_kst,
    )

    db.add(auth_phone)
    db.commit()

    params = {
        "type": "sms",
        "to": request.phone_number,
        "from": SENDER_NUMBER,
        "text": f"인증번호는 {verification_code}입니다.",
    }
    cool = Message(API_KEY, API_SECRET)
    try:
        response = cool.send(params)
        if response["success_count"] > 0:
            logger.info(f"SMS sent successfully to {request.phone_number}")
            return {"message": "SMS sent successfully"}
        else:
            logger.error(f"Failed to send SMS to {request.phone_number}")
            raise HTTPException(status_code=400, detail="Failed to send SMS")

    except CoolsmsException as e:
        logger.error(f"Internal Server Error: {e.msg}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e.msg}")

@app.post("/verify_sms/")
def verify_sms(request: VerifyCodeRequest, db: Session = Depends(get_db)):
    current_time_kst = datetime.now(tz=KST)
    auth_phone = (
        db.query(AuthPhone)
        .filter(
            AuthPhone.phone_number == request.phone_number,
            AuthPhone.auth_code == request.auth_code,
            AuthPhone.expires_at > current_time_kst,
            AuthPhone.is_verified == False,
        )
        .first()
    )

    if not auth_phone:
        logger.warning(
            f"Invalid or expired verification code for {request.phone_number}"
        )
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification code"
        )

    auth_phone.is_verified = True
    db.commit()

    user = db.query(User).filter(User.contact == request.phone_number).first()

    if user:
        token = create_access_token(user.student_number)
        auth_token = AuthToken(
            student_number=user.student_number,
            token_type="access",
            token=token,
            created_at=current_time_kst,
            expires_at=current_time_kst + timedelta(hours=1),
        )
        db.add(auth_token)
        db.commit()
        logger.info(f"Login successful for {user.student_number}")
        return {"message": "Login successful", "token": token}
    else:
        logger.info(
            f"Verification successful for {request.phone_number}, proceed to signup"
        )
        return {"message": "Verification successful, proceed to signup"}

@app.post("/signup/")
def signup(request: UserSignupRequest, db: Session = Depends(get_db)):
    signup_date_kst = datetime.now(tz=KST)
    user = User(
        student_number=request.student_number,
        name=request.name,
        email=request.email,
        contact=request.contact,
        department=request.department,
        signup_date=signup_date_kst,
    )
    db.add(user)
    db.commit()

    token = create_access_token(user.student_number)
    auth_token = AuthToken(
        student_number=user.student_number,
        token_type="access",
        token=token,
        created_at=signup_date_kst,
        expires_at=signup_date_kst + timedelta(hours=1),
    )
    db.add(auth_token)
    db.commit()

    logger.info(f"Signup successful for {request.student_number}")
    return {"message": "Signup successful", "token": token}

@app.get("/create_vm_with_keypair")
async def create_vm_with_keypair(
    access_key_id: str = Query(..., description="API 접근을 위한 액세스 키 ID"),
    access_key_secret: str = Query(..., description="API 접근을 위한 액세스 키 시크릿"),
    keypair_name: str = Query(..., description="생성할 키페어 이름"),
    vm_name: str = Query(..., description="생성할 VM 이름"),
    image_ref: str = Query(..., description="이미지 ID"),
    flavor_ref: str = Query(..., description="인스턴스 유형 ID"),
    network_id: str = Query(..., description="네트워크 ID"),
    availability_zone: str = Query("kr-central-2-a", description="가용 영역"),
    description: str = Query("My VM", description="VM 설명"),
    security_group_name: str = Query("default", description="보안 그룹 이름"),
    volume_size: int = Query(30, description="루트 볼륨 크기 (GB)"),
    email_to: str = Query(..., description="키 페어와 VM 정보를 보낼 이메일 주소"),
):
    # API 토큰 발급
    url_token = "https://iam.kakaocloud.com/identity/v3/auth/tokens"
    payload_token = {
        "auth": {
            "identity": {
                "methods": ["application_credential"],
                "application_credential": {
                    "id": access_key_id,
                    "secret": access_key_secret,
                },
            }
        }
    }
    headers_token = {"Content-Type": "application/json"}
    response_token = requests.post(url_token, json=payload_token, headers=headers_token)

    if response_token.status_code != 201:
        raise HTTPException(
            status_code=response_token.status_code, detail="Failed to obtain token"
        )

    token = response_token.headers.get("X-Subject-Token")
    print(f"Token obtained: {token}")

    # 키페어 생성
    url_keypair = "https://0ec59da8-9bdb-465f-993f-eee695fc12aa.api.kr-central-2.kakaoi.io/api/v2/virtual-machine/keypair"
    headers_keypair = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-Auth-Token": token,
    }
    data_keypair = {"name": keypair_name, "type": "ssh"}
    response_keypair = requests.post(url_keypair, headers=headers_keypair, json=data_keypair)

    if response_keypair.status_code != 200:
        raise HTTPException(
            status_code=response_keypair.status_code, detail="Failed to create keypair"
        )

    response_json = response_keypair.json()
    private_key = response_json.get("keypair", {}).get("private_key")
    print(f"Keypair creation response: {response_json}")

    if private_key:
        key_save_path = os.path.expanduser(f"/home/ubuntu/keypairs/{keypair_name}.pem")
        os.makedirs(os.path.dirname(key_save_path), exist_ok=True)
        with open(key_save_path, "w") as file:
            file.write(private_key)
        print(f"Keypair created and saved at {key_save_path}")
    else:
        raise HTTPException(status_code=500, detail="Private key not found")

    # VM 생성
    url_vm = "https://0ec59da8-9bdb-465f-993f-eee695fc12aa.api.kr-central-2.kakaoi.io/api/v2/virtual-machine/instances"
    headers_vm = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-Auth-Token": token,
    }
    data_vm = {
        "count": 1,
        "name": vm_name,
        "description": description,
        "imageRef": image_ref,
        "availabilityZone": availability_zone,
        "disableHyperthreading": False,
        "flavorRef": flavor_ref,
        "keyName": keypair_name,
        "networks": [{"uuid": network_id}],
        "securityGroups": [{"name": security_group_name}],
        "userData": "",
        "volumes": [
            {"isRoot": True, "deleteOnTermination": True, "volumeSize": volume_size}
        ],
    }

    response_vm = requests.post(url_vm, headers=headers_vm, json=data_vm)

    if response_vm.status_code != 202:
        raise HTTPException(
            status_code=response_vm.status_code, detail="Failed to create VM"
        )

    response_json = response_vm.json()
    vm_id = response_json.get("server", {}).get("id")
    print(f"VM creation response: {response_json}")

    if not vm_id:
        raise HTTPException(status_code=500, detail="VM ID not found")

    # VM이 활성화될 때까지 대기
    def get_vm_instances(auth_token, limit=20):
        url = "https://0ec59da8-9bdb-465f-993f-eee695fc12aa.api.kr-central-2.kakaoi.io/api/v2/virtual-machine/instances"
        headers = {"X-Auth-Token": auth_token, "Content-Type": "application/json"}
        params = {"limit": limit}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            print("Successfully fetched VM instances.")
            instances = response.json()
            if isinstance(instances, list):
                return instances
            return instances.get("servers", [])
        else:
            print(
                f"Failed to fetch VM instances: {response.status_code}, {response.text}"
            )
            return None

    instance_status = None
    while True:
        instances = get_vm_instances(token)
        if instances:
            for instance in instances:
                if instance["name"] == vm_name:
                    instance_status = instance.get("status", None)
                    print(f"Current status of VM '{vm_name}': {instance_status}")
                    break

        if instance_status and instance_status.lower() == "active":
            print(f"VM '{vm_name}' is now ACTIVE.")
            break
        else:
            print(
                f"VM '{vm_name}' is not yet ACTIVE, current status: {instance_status}"
            )
            time.sleep(2)

    # 퍼블릭 IP 생성
    def get_floating_ips(auth_token):
        url = "https://0ec59da8-9bdb-465f-993f-eee695fc12aa.api.kr-central-2.kakaoi.io/api/v2/virtual-machine/floating-ips"
        headers = {
            "X-Auth-Token": auth_token,
            "Accept": "application/json",
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("Successfully fetched floating IPs.")
            return response.json()
        else:
            print(
                f"Failed to get floating IPs: {response.status_code}, {response.text}"
            )
            return None

    def assign_floating_ip(auth_token, floating_ip_id, vm_id):
        url = f"https://0ec59da8-9bdb-465f-993f-eee695fc12aa.api.kr-central-2.kakaoi.io/api/v2/virtual-machine/instances/{vm_id}/floating-ip"
        headers = {
            "X-Auth-Token": auth_token,
            "Content-Type": "application/json",
        }
        data = {"floatingIpId": floating_ip_id}
        response = requests.post(url, headers=headers, data=json.dumps(data))
        if response.status_code == 202:
            print("Successfully assigned floating IP.")
        else:
            print(
                f"Failed to assign floating IP: {response.status_code}, {response.text}"
            )
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to assign floating IP: {response.text}",
            )

    floating_ips = get_floating_ips(token)
    if floating_ips:
        floating_ip_id = floating_ips[0]["id"]
        assign_floating_ip(token, floating_ip_id, vm_id)

        floating_ip_address = None
        while True:
            instances = get_vm_instances(token)
            if instances:
                for instance in instances:
                    if instance["name"] == vm_name:
                        for address in instance.get("addresses", []):
                            if "floatingIp" in address:
                                floating_ip_address = address["floatingIp"]
                                break
                        if floating_ip_address:
                            break

            if floating_ip_address:
                print(f"퍼블릭 IP가 부여되었습니다: {floating_ip_address}")
                break
            else:
                print("퍼블릭 IP가 아직 부여되지 않았습니다. 2초 후 다시 확인합니다.")
                time.sleep(2)

        if not floating_ip_address:
            print("Failed to retrieve the floating IP address.")
            raise HTTPException(
                status_code=500, detail="Failed to retrieve the floating IP address."
            )
    else:
        print("No available floating IPs found.")
        raise HTTPException(status_code=404, detail="No available floating IPs found")

    # 이메일 전송
    sender_email = "jjinjukks1227@naver.com"
    sender_password = "dltjdgus!159"
    receiver_email = email_to

    body = f"""키 페어 및 VM 정보:

    키 페어 이름: {keypair_name}
    VM 이름: {vm_name}
    퍼블릭 IP: {floating_ip_address}
    이미지 ID: {image_ref}
    인스턴스 유형 ID: {flavor_ref}

    SSH 접속 명령어:
    ssh -i ~/Downloads/{keypair_name}.pem ubuntu@{floating_ip_address}
    """

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = f"{vm_name} VM 정보 및 키 페어"

    message.attach(MIMEText(body, "plain"))

    # 키 페어 파일 첨부
    with open(f"/home/ubuntu/keypairs/{keypair_name}.pem", "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {keypair_name}.pem",
    )

    message.attach(part)

    try:
        server = smtplib.SMTP("smtp.naver.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {
        "message": f"VM created and assigned floating IP: {floating_ip_address}, email sent to {receiver_email}",
        "floating_ip_address": floating_ip_address,
        "keypair_name": keypair_name,
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
