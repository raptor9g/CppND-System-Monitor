#include "ProcessParser.h"
#include <regex>

std::string ProcessParser::getCmd(string pid)
{

  std::ifstream fileStream;
  Util::getStream(Path::basePath() + pid + Path::cmdPath(), fileStream);
  std::string line;
  std::getline(fileStream, line);
  return line;

}

std::vector<string> ProcessParser::getPidList()
{
  
  DIR* dir;

  std::regex re("^[0-9]+$");

  std::vector<std::string> container;
  
  if(!(dir = opendir("/proc")))
      throw std::runtime_error(std::strerror(errno));

  while (dirent* dirp = readdir(dir)) {

      if(dirp->d_type != DT_DIR){
          continue;
      }
      if (std::regex_match(dirp->d_name, re)) {
          container.push_back(dirp->d_name);
      }
  }
  //Validating process of directory closing
  if(closedir(dir))
      throw std::runtime_error(std::strerror(errno));
  return container;
}

std::string ProcessParser::getVmSize(string pid)
{
  std::string findName = "VmData";
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + pid + Path::statusPath(), fileStream);
  std::string line;
  float result = 0.0;
  while(std::getline(fileStream, line)){

    if(line.find(findName) == 0){

      std::istringstream lineBuf(line);
      std::istream_iterator<std::string> iter(lineBuf), end;

      if(++iter != end){

        result = std::stof(*iter)/float(1024*1024);
        break;
      
      }

    }

  }

  return std::to_string(result);


}

std::string ProcessParser::getCpuPercent(string pid)
{

  std::ifstream fileStream;
  Util::getStream(Path::basePath() + pid + Path::statPath(), fileStream);
  std::string line;
  std::getline(fileStream, line);
  std::istringstream lineBuf(line);
  std::istream_iterator<std::string> iter(lineBuf);

  std::advance(iter, 14); //pos 14
  float stime = std::stof(*iter);
  float cutime = std::stof(*(++iter)); //pos 15
  float cstime = std::stof(*(++iter)); //pos 16
  std::advance(iter, 5); //pos 21
  float starttime = std::stof(*iter);

  float utime = stof(ProcessParser::getProcUpTime(pid));

  float uptime = ProcessParser::getSysUpTime();
  
  float freq = sysconf(_SC_CLK_TCK);
  float total_time = utime + stime + cutime + cstime;
  float seconds = uptime - (starttime/freq);
  float result = 100.0*((total_time/freq)/seconds);
  return to_string(result);

}

long int ProcessParser::getSysUpTime()
{

  std::ifstream fileStream;
  Util::getStream(Path::basePath() + Path::upTimePath(), fileStream);
  std::string line;
  std::getline(fileStream, line);
  std::istringstream buf(line);
  std::istream_iterator<string> iter(buf);
  
  return stoi(*iter);

}

std::string ProcessParser::getProcUpTime(string pid)
{
  
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + pid + Path::statPath(), fileStream);
  std::string line;
  std::getline(fileStream, line);
  std::istringstream lineBuf(line);
  std::istream_iterator<std::string> iter(lineBuf);

  std::advance(iter, 13); //pos 13

  return std::to_string(float(std::stof(*iter)/sysconf(_SC_CLK_TCK)));

}

std::string ProcessParser::getProcUser(string pid)
{

  std::string findName = "Uid:";
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + pid + Path::statusPath(), fileStream);
  std::string line;
  std::string uid;
  while(std::getline(fileStream, line)){

    if(line.find(findName) == 0){

      std::istringstream lineBuf(line);
      std::istream_iterator<std::string> iter(lineBuf), end;

      if(++iter != end){

        uid.append(*iter);
        break;
      
      }

    }

  }
  
  Util::getStream("/etc/passwd", fileStream);
  findName = "x:" + uid;
  while (std::getline(fileStream, line)) {
    if (line.find(findName) != std::string::npos) {
      return line.substr(0, line.find(":"));
    }
  }
  
  return "";

}

std::vector<string> ProcessParser::getSysCpuPercent(string coreNumber)
{

  std::ifstream fileStream; 
  Util::getStream(Path::basePath() + Path::statPath(), fileStream);
  std::string findName("cpu" + coreNumber);
  std::string line;
  while (std::getline(fileStream, line)) {
      if (line.find(findName) == 0) {
          istringstream lineBuf(line);
          istream_iterator<string> iter(lineBuf), end;
          std::vector<string> values(iter, end);
          // set of cpu data active and idle times;
          return values;
      }
  }
  return std::vector<string>();

}

float ProcessParser::getSysRamPercent()
{

  std::string findMemAvail = "MemAvailable:";
  std::string findMemFree = "MemFree:";
  std::string findBuf = "Buffers:";

  int result;
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + Path::memInfoPath(), fileStream);
  
  float total_mem = 0;
  float free_mem = 0;
  float buffers = 0;
  
  std::string line;
  std::string value;
  
  while (std::getline(fileStream, line)) {
      
      if (total_mem != 0 && free_mem != 0){
          break;
      }

      if (line.find(findMemAvail) == 0) {
          istringstream lineBuf(line);
          istream_iterator<string> iter(lineBuf);
          total_mem = stof(*(++iter));
      }

      if (line.find(findMemFree) == 0) {
          istringstream lineBuf(line);
          istream_iterator<string> iter(lineBuf);
          free_mem = stof(*(++iter));
      }

      if (line.find(findBuf) == 0) {
          istringstream lineBuf(line);
          istream_iterator<string> iter(lineBuf);
          buffers = stof(*(++iter));
      }
 
  }
 
  //calculating usage:
  return float(100.0*(1-(free_mem/(total_mem-buffers))));

}

std::string ProcessParser::getSysKernelVersion()
{
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + Path::versionPath(), fileStream);
  
  std::string line;
  std::string findName = "Linux version";
  
  while (std::getline(fileStream, line)) {
      
      if (line.find(findName) == 0) {
          std::istringstream lineBuf(line);
          std::istream_iterator<string> iter(lineBuf);
          std::advance(iter, 2);
          return *iter;
      }
  
  }

  return "";
}

int ProcessParser::getNumberOfCores()
{

  std::string findName = "cpu cores";
  std::ifstream fileStream;
  Util::getStream(Path::basePath() + "cpuinfo", fileStream);
  std::string line;
  while(std::getline(fileStream, line)){

    if(line.find(findName) == 0){

      std::istringstream lineBuf(line);
      std::istream_iterator<std::string> iter(lineBuf);

      std::advance(iter, 3);

      return std::stoi(*iter);

    }

  }

  return 0;

}

int ProcessParser::getTotalThreads()
{

  int numThreads = 0;

  std::string findName("Threads:");
  std::ifstream fileStream;
  std::string line;
  
  for (auto pid : ProcessParser::getPidList()) {

    Util::getStream(Path::basePath() + pid + Path::statusPath(), fileStream);
    
    while (std::getline(fileStream, line)) {
       
        if (line.find(findName) == 0) {
            
          std::istringstream lineBuf(line);
          std::istream_iterator<string> iter(lineBuf);
          numThreads += std::stoi(*(++iter));
          break;
        }
    
    }

  }

  return numThreads;

}

int ProcessParser::getTotalNumberOfProcesses()
{
  int numProcesses = 0;
  std::string line;
  std::string findName("processes");
  std::ifstream fileStream;
  
  Util::getStream(Path::basePath() + Path::statPath(), fileStream);
  
  while (std::getline(fileStream, line)) {
      if (line.find(findName) == 0) {
          std::istringstream lineBuf(line);
          std::istream_iterator<string> iter(lineBuf);
          numProcesses += stoi(*(++iter));
          break;
      }
  }
  
  return numProcesses;

}

int ProcessParser::getNumberOfRunningProcesses()
{

  int numRunningProcesses = 0;
  std::string line;
  std::string findName("procs_running");
  std::ifstream fileStream;
  
  Util::getStream(Path::basePath() + Path::statPath(), fileStream);
  
  while (std::getline(fileStream, line)) {
 
    if(line.find(findName) == 0) {
        std::istringstream lineBuf(line);
        std::istream_iterator<string> iter(lineBuf);
        numRunningProcesses += stoi(*(++iter));
        break;
    }
 
  }
  
  return numRunningProcesses;

}

std::string ProcessParser::getOSName()
{

  std::ifstream fileStream;
  Util::getStream("/etc/os-release", fileStream);

  std::string line;
  std::regex re("PRETTY_NAME=\"([^\"]+)\"");
  std::smatch m;
  while (std::getline(fileStream, line)) {

      if (std::regex_search(line,m,re)) {
           
            return *(++(m.begin()));
      
      }
  
  }

  return "";

}

float ProcessParser::getSysActiveCpuTime(std::vector<std::string> values)
{
    return (std::stof(values[S_USER]) +
            std::stof(values[S_NICE]) +
            std::stof(values[S_SYSTEM]) +
            std::stof(values[S_IRQ]) +
            std::stof(values[S_SOFTIRQ]) +
            std::stof(values[S_STEAL]) +
            std::stof(values[S_GUEST]) +
            std::stof(values[S_GUEST_NICE]));
}

float ProcessParser::getSysIdleCpuTime(std::vector<std::string>values)
{
    return (std::stof(values[S_IDLE]) + std::stof(values[S_IOWAIT]));
}

std::string ProcessParser::PrintCpuStats(
  std::vector<std::string> values1,
  std::vector<std::string>values2
)
{
  float activeTime = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
  float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
  float totalTime = activeTime + idleTime;
  float result = 100.0*(activeTime / totalTime);
  return to_string(result);
}

bool ProcessParser::isPidExisting(std::string pid)
{
  auto pids = getPidList();
  return std::find(pids.begin(), pids.end(), pid) != pids.end();
}