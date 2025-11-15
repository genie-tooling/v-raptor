from .database import Finding, ChatMessage, QualityInterpretation
from .llm import LLMService


class ChatService:
    def __init__(self, db_session, llm_service: LLMService):
        self.db_session = db_session
        self.llm_service = llm_service

    def chat_with_finding(self, finding_id, message):

        """Chats with a finding."""

        finding = self.db_session.query(Finding).get(finding_id)

        if not finding:
            return "Finding not found."

        # Store user message
        user_message = ChatMessage(finding_id=finding_id, message=message, sender='user')
        self.db_session.add(user_message)
        self.db_session.commit()

        history = self.db_session.query(ChatMessage).filter_by(finding_id=finding_id).order_by(ChatMessage.created_at).all()
        prompt = f"""You are a senior security engineer. You are chatting with a developer about the following vulnerability:

Description: {finding.description}
File: {finding.file_path}
Line: {finding.line_number}
Code Snippet:
```
{finding.code_snippet}
```
Here is the chat history:

"""
        for msg in history:
            prompt += f"{msg.sender}: {msg.message}\n"
        prompt += "\nProvide a direct, concise, and helpful response to the last message from the user. Provide deep insight into how the vulnerability affects the security of their program and how to fix it. Do not ask any questions or be conversational."
        response = self.llm_service._create_chat_completion(
            self.llm_service.scanner_client,
            self.llm_service._get_model_name('scanner'),
            prompt,
            is_json=False
        )



        # Store assistant message

        assistant_message = ChatMessage(finding_id=finding_id, message=response, sender='assistant')

        self.db_session.add(assistant_message)

        self.db_session.commit()



        return response



    def chat_with_quality_interpretation(self, interpretation_id, message):
        """Chats with a quality interpretation."""
        interpretation = self.db_session.query(QualityInterpretation).get(interpretation_id)
        if not interpretation:
            return "Interpretation not found."

        # Store user message

        user_message = ChatMessage(quality_interpretation_id=interpretation_id, message=message, sender='user')
        self.db_session.add(user_message)
        self.db_session.commit()

        history = self.db_session.query(ChatMessage).filter_by(quality_interpretation_id=interpretation_id).order_by(ChatMessage.created_at).all()

        prompt = f"""You are a senior software engineer and code quality expert. You are chatting with a developer about the following code quality interpretation:

File: {interpretation.quality_metric.file_path}
Interpretation:
{interpretation.interpretation}

Here is the chat history:

"""
        for msg in history:
            prompt += f"{msg.sender}: {msg.message}\n"

        prompt += "\nProvide a direct, concise, and helpful response to the last message from the user. Provide helpful information on how to fix the quality issues. Do not ask any questions or be conversational."
        response = self.llm_service._create_chat_completion(
            self.llm_service.scanner_client,
            self.llm_service._get_model_name('scanner'),
            prompt,
            is_json=False
        )
        # Store assistant message
        assistant_message = ChatMessage(quality_interpretation_id=interpretation_id, message=response, sender='assistant')
        self.db_session.add(assistant_message)
        self.db_session.commit()
        return response
