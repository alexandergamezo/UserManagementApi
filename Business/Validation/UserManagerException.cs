using System.Runtime.Serialization;

namespace Business.Validation
{
    [Serializable]
    public class UserManagerException : Exception
    {
        public UserManagerException(string message) : base(message)
        {            
        }

        protected UserManagerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }

        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
        }
    }
}
